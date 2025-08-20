#include "obfuscator.hpp"

namespace obfuscator::utils {
	bool does_fn_contain_jump_table(const ZydisDisassembledInstruction& inst, const uint64_t image_base) { //for now will do the simple heuristic of finding if the program does lea <reg>, [image base addr]. will be some false positives though
		if (inst.info.mnemonic != ZYDIS_MNEMONIC_LEA)
			return false;

		if (!inst.operands)
			return false;

		if (inst.operands[1].visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT || inst.operands[2].visibility != ZYDIS_OPERAND_VISIBILITY_INVALID)
			return false;

		uint64_t lea_addr;
		if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst.info, &inst.operands[1], inst.runtime_address, &lea_addr)))
			return false; // if we're here, means I missed something in the checks above and this isn't the instruction we're looking for anyways

		return lea_addr == image_base;
	}
}

bool Obfuscator::potential_control_flow_fix_up(const ZydisDisassembledInstruction& inst) {
	auto category = inst.info.meta.category;
	if (category != ZYDIS_CATEGORY_COND_BR && category != ZYDIS_CATEGORY_UNCOND_BR && category != ZYDIS_CATEGORY_CALL)
		return false;

	auto operand = inst.operands[0];
	if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		return true;

	if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
		return operand.mem.base == ZYDIS_REGISTER_RIP;

	return false;
}

int8_t Obfuscator::get_rip_explicit_operand_index(const ZydisDisassembledInstruction& inst) {
	for (int i = 0; i < inst.info.operand_count_visible; i++) {
		const auto& operand = inst.operands[i];
		if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER && operand.reg.value == ZYDIS_REGISTER_RIP)
			return i;

		if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == ZYDIS_REGISTER_RIP)
			return i;
	}

	return EXPLICIT_RIP_OPERAND_NO_FIX_INDEX;
}


uint64_t Obfuscator::get_fn_entry_addr(const uint64_t img_rel_fn_start_addr, const uint64_t img_rel_start, const uint64_t img_rel_end) {
	uint64_t section_size = img_rel_end - img_rel_start;
	auto content = this->pe->get_content_from_virtual_address(img_rel_start, section_size);

	for (size_t i = 0; i < content.size() - i*sizeof(uint64_t); i++) {
		uint64_t entry = *reinterpret_cast<const uint64_t*>(&content[i * sizeof(uint64_t)]);
		uint64_t img_rel_entry = entry - pe->imagebase();
		if (img_rel_fn_start_addr == img_rel_entry)
			return img_rel_start + i * sizeof(uint64_t);
	}

	return 0;
}

void Obfuscator::init_fns(const std::filesystem::path& executable_path) {
	if (!this->pe)
		throw std::runtime_error("the obfuscator isn't linked to any pe file.");

	auto text_section = this->pe->get_section(".text");
	const auto text = text_section->content();

	PdbParser parser;
	auto parser_result = parser.parse_pdb(executable_path, text_section->virtual_address(), text_section->virtual_size());
	if (!parser_result)
		throw std::runtime_error(std::format("Something went wrong when parsing the pdb, {}", parser_result.error()));

	auto user_ctx = *parser_result;
	const uint64_t start_crt_entries[] = { user_ctx.crt.__xi_a, user_ctx.crt.__xc_a, user_ctx.crt.__xp_a, user_ctx.crt.__xt_a };
	const uint64_t end_crt_entries[] = { user_ctx.crt.__xi_z, user_ctx.crt.__xc_z, user_ctx.crt.__xp_z, user_ctx.crt.__xt_z };
	for (const auto& fn : user_ctx.fn_info_vec) {
		if (fn.img_rel_start_addr < text_section->virtual_address() || fn.img_rel_start_addr + fn.fn_size > text_section->virtual_address() + text_section->virtual_size())
			throw std::runtime_error("a function in the pdb file lies outside the bound of .text");

		types::func_t obfuscator_fn = { .img_rel_start_addr = fn.img_rel_start_addr, .fn_size = fn.fn_size, .is_entry_point = fn.img_rel_start_addr == this->pe->optional_header().addressof_entrypoint() };
		const auto fn_code = text.subspan(fn.img_rel_start_addr - text_section->virtual_address(), fn.fn_size);

		//checking if the function is getting called by crt. Need to check this to update the entries if the fn start addr gets modified
		uint64_t fn_crt_entry_ptr = 0;
		for (int i = 0; i < sizeof(start_crt_entries) / sizeof(start_crt_entries[0]); i++) {
			fn_crt_entry_ptr = this->get_fn_entry_addr(obfuscator_fn.img_rel_start_addr, start_crt_entries[i], end_crt_entries[i]);
			if (fn_crt_entry_ptr)
				break;
		}

		obfuscator_fn.crt_entry = fn_crt_entry_ptr;

		//decoding and checking that there is no jump table, if there is we stop at the first ret instruction and assume the remaining is jump_table data
		uint64_t runtime_address = pe->imagebase() + obfuscator_fn.img_rel_start_addr;
		uint64_t offset = 0;
		while (offset < obfuscator_fn.fn_size) {
			ZydisDisassembledInstruction instruction;
			if (ZYAN_SUCCESS(ZydisDisassembleIntel(
				/* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
				/* runtime_address: */ runtime_address + offset,
				/* buffer:          */ fn_code.data() + offset,
				/* length:          */ obfuscator_fn.fn_size - offset,
				/* instruction:     */ &instruction
			))) {
				if (obfuscator::utils::does_fn_contain_jump_table(instruction, pe->imagebase()))
					obfuscator_fn.has_jump_table = true;

				if (obfuscator_fn.has_jump_table && instruction.info.mnemonic == ZYDIS_MNEMONIC_RET)
					break; //what follows should be the jump table (+ some padding)
				
				types::instruction_wrapper_t inst = { .inst = instruction };
				inst.control_flow_might_need_fix = this->potential_control_flow_fix_up(instruction);

				inst.explicit_rip_operand_index = this->get_rip_explicit_operand_index(instruction);
				if (inst.needs_explicit_operand_fix()) {
					uint64_t dst_addr;
					if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction.info, &instruction.operands[inst.explicit_rip_operand_index], instruction.runtime_address, &dst_addr)))
						throw std::runtime_error(std::format("Failed to calculate absolute address of jump at instruction {:#x}", instruction.runtime_address - this->pe->imagebase()));

					uint64_t img_rel_dst_addr = dst_addr - this->pe->imagebase();
					auto section = this->pe->section_from_rva(img_rel_dst_addr);
					if (section) //if no section found, could be a lea reg, [image_base_addr] for ex
						inst.references_outside_of_dot_text = section->name().compare(".text");
				}


				obfuscator_fn.decoded_insts_wrappers.push_back(inst);
				offset += instruction.info.length;
			} else {
				throw std::runtime_error(std::format("Zydis failed to decode an instruction at {:#x} rva", obfuscator_fn.img_rel_start_addr + offset));
			}
		}

		this->funcs.push_back(obfuscator_fn);
	}

	//sorting functions by ascending orders
	std::sort(this->funcs.begin(), this->funcs.end());

	ZydisDisassembledInstruction instruction;
	for (const auto& potential_jump_stub_addr : user_ctx.potential_jump_stubs) {
		uint64_t text_rel_jump_addr = potential_jump_stub_addr - text_section->virtual_address();
		if (!ZYAN_SUCCESS(ZYAN_SUCCESS(ZydisDisassembleIntel(
			/* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
			/* runtime_address: */ pe->imagebase() + potential_jump_stub_addr,
			/* buffer:          */ text.data() + text_rel_jump_addr,
			/* length:          */ text_section->virtual_size() - text_rel_jump_addr,
			/* instruction:     */ &instruction))))
			continue;

		if (!this->potential_control_flow_fix_up(instruction))
			continue;

		auto operand = instruction.operands[0];
		//the check belows filters out the inop from cfg that are jmp rax
		if (instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP && operand.mem.base == ZYDIS_REGISTER_RIP) //there's a risk that this might be vs compiler specific, might need to implement something more flexible
			this->outside_fns_rip_jump_stubs.push_back({ .inst = instruction, .control_flow_might_need_fix = true, .references_outside_of_dot_text = true }); //save the whole instruction so that we can rebuild them later with Zydis's encoder
	}
}

Obfuscator::Obfuscator(const std::filesystem::path& executable_path) :
	pe(LIEF::PE::Parser::parse(executable_path.string())),
	binary_fixer(pe.get())
{
	this->init_fns(executable_path);
	this->binary_fixer = BinaryFixer(this->pe.get());
}

void Obfuscator::run_passes() {
	auto text_section = this->pe->get_section(".text");
	auto after_pass_text = passes::anti_disassembly::ebff_decoy(this->binary_fixer, text_section->content(), this->pe->imagebase(), text_section->virtual_address(), this->funcs, this->outside_fns_rip_jump_stubs); //should be run later when adding other passes
	text_section->content(after_pass_text);

	this->binary_fixer.fix_crt_entries(this->funcs);
	if (!this->binary_fixer.fix_entrypoint_addr(this->funcs))
		throw std::runtime_error("Failed to update entrypoint function, no such function found.");
	
}

void Obfuscator::build_executable(const std::filesystem::path& out) {
	LIEF::PE::Builder builder(*this->pe);
	builder.build();
	builder.write(out.string());
}
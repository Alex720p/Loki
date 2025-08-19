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

std::expected<void, std::string> Obfuscator::init_fns(const std::filesystem::path& executable_path) {
	if (!this->pe)
		throw std::runtime_error("the obfuscator isn't linked to any pe file.");

	auto text_section = this->pe->get_section(".text");
	const auto text = text_section->content();

	PdbParser parser;
	auto parser_result = parser.parse_pdb(executable_path, text_section->virtual_address(), text_section->virtual_size());
	if (!parser_result)
		return std::unexpected(parser_result.error());

	auto user_ctx = *parser_result;
	const uint64_t start_crt_entries[] = { user_ctx.crt.__xi_a, user_ctx.crt.__xc_a, user_ctx.crt.__xp_a, user_ctx.crt.__xt_a };
	const uint64_t end_crt_entries[] = { user_ctx.crt.__xi_z, user_ctx.crt.__xc_z, user_ctx.crt.__xp_z, user_ctx.crt.__xt_z };
	for (const auto& fn : user_ctx.fn_info_vec) {
		if (fn.fn_start_addr_rel < text_section->virtual_address() || fn.fn_start_addr_rel + fn.fn_size > text_section->virtual_address() + text_section->virtual_size())
			return std::unexpected("a function in the pdb file lies outside the bound of .text");

		types::obfuscator::func_t obfuscator_fn = { .fn_start_addr_rel = fn.fn_start_addr_rel, .fn_size = fn.fn_size, .is_entry_point = fn.fn_start_addr_rel == this->pe->optional_header().addressof_entrypoint() };
		const auto fn_code = text.subspan(fn.fn_start_addr_rel - text_section->virtual_address(), fn.fn_size);

		//checking if the function is getting called by crt. Need to check this to update the entries if the fn start addr gets modified
		uint64_t fn_crt_entry_ptr = 0;
		for (int i = 0; i < sizeof(start_crt_entries) / sizeof(start_crt_entries[0]); i++) {
			fn_crt_entry_ptr = this->get_fn_entry_addr(obfuscator_fn.fn_start_addr_rel, start_crt_entries[i], end_crt_entries[i]);
			if (fn_crt_entry_ptr)
				break;
		}

		obfuscator_fn.crt_entry = fn_crt_entry_ptr;

		//decoding and checking that there is no jump table, in which case we skip the whole fn for now
		uint64_t runtime_address = pe->imagebase() + obfuscator_fn.fn_start_addr_rel;
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
				
				obfuscator_fn.decoded_insts.push_back(instruction);
				offset += instruction.info.length;
			} else {
				return std::unexpected(std::format("Zydis failed to decode an instruction at {:#x} rva", obfuscator_fn.fn_start_addr_rel + offset));
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

		if (!helpers::is_inst_control_flow_op(instruction))
			continue;

		auto operand = instruction.operands[0];
		if (instruction.info.mnemonic == ZYDIS_MNEMONIC_JMP && operand.mem.base == ZYDIS_REGISTER_RIP) //there's a risk that this might be vs compiler specific, might need to implement something more flexible
			this->outside_fns_rip_jump_stubs.push_back(instruction); //save the whole instruction so that we can rebuild them later with Zydis's encoder
	}
}

Obfuscator::Obfuscator(const std::filesystem::path& executable_path) :
	pe(LIEF::PE::Parser::parse(executable_path.string())),
	binary_fixer(pe.get())
{
	auto fn_init_res = this->init_fns(executable_path);
	if (!fn_init_res)
		throw std::runtime_error(std::format("Failed to init functions in obfuscator, error: {}", fn_init_res.error()));

	this->binary_fixer = BinaryFixer(this->pe.get());
	this->is_funcs_valid = true;
}

void Obfuscator::run_passes() {
	auto text_section = this->pe->get_section(".text");
	auto pass_ret = passes::anti_disassembly::ebff_decoy(this->binary_fixer, text_section->content(), this->pe->imagebase(), text_section->virtual_address(), this->funcs, this->outside_fns_rip_jump_stubs); //should be run later when adding other passes
	if (!pass_ret)
		throw std::runtime_error(std::format("Failed to run pass. {}", pass_ret.error()));

	text_section->content(*pass_ret); //TODO: UPDATE RUNTIME_ADDRESS IN INSTRUCTIONS

	this->binary_fixer.fix_crt_entries(this->funcs);
	//updating the entrypoint
	for (const auto& fn : this->funcs) {
		if (fn.is_entry_point) {
			this->pe->optional_header().addressof_entrypoint(fn.fn_start_addr_rel);
			break;
		}
	}
}

void Obfuscator::build_obfuscated_executable(const std::filesystem::path& out) {
	LIEF::PE::Builder builder(*this->pe);
	builder.build();
	builder.write(out.string());
}
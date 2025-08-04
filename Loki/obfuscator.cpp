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


std::expected<void, std::string> Obfuscator::init_fns(const std::filesystem::path& executable_path) {
	if (!this->pe)
		return std::unexpected("the obfuscator isn't linked to any pe file.");

	auto text_section = this->pe->get_section(".text");
	const auto text = text_section->content();

	PdbParser parser;
	auto parser_result = parser.parse_pdb(executable_path);
	if (!parser_result)
		return std::unexpected(parser_result.error());

	auto user_ctx = *parser_result;
	for (const auto& fn : user_ctx.fn_info_vec) {
		if (fn.fn_start_addr_rel < text_section->virtual_address() || fn.fn_start_addr_rel + fn.fn_size > text_section->virtual_address() + text_section->virtual_size())
			return std::unexpected("a function in the pdb file lies outside the bound of .text");

		types::obfuscator::func_t obfuscator_fn = { .fn_start_addr_rel = fn.fn_start_addr_rel, .fn_size = fn.fn_size };
		const auto fn_code = text.subspan(fn.fn_start_addr_rel - text_section->virtual_address(), fn.fn_size);

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
				if (obfuscator::utils::does_fn_contain_jump_table(instruction, pe->imagebase())) {
					obfuscator_fn.has_jump_table = true;
					obfuscator_fn.decoded_insts.clear(); //we won't need the list anymore for now. note: in future imp, will try to detect the jump table and its location and do some obfuscation around/ on it
					break;
				}
				
				obfuscator_fn.decoded_insts.push_back(instruction);
				offset += instruction.info.length;
			} else {
				return std::unexpected(std::format("Zydis failed to decode an instruction at {} rva", obfuscator_fn.fn_start_addr_rel + offset));
			}
		}

		this->funcs.push_back(obfuscator_fn);
	}

	//sorting functions by ascending orders
	std::sort(this->funcs.begin(), this->funcs.end());

	for (const auto& potential_jump_stub : user_ctx.potential_jump_stubs) {

	}
}

void Obfuscator::init(const std::filesystem::path& executable_path) {
	this->pe = LIEF::PE::Parser::parse(executable_path.string());
	auto fn_init_res = this->init_fns(executable_path);
	if (!fn_init_res)
		throw std::runtime_error(std::format("failed to init functions in obfuscator, error: {}", fn_init_res.error()));

	this->is_funcs_valid = true;
}


void Obfuscator::run_passes() {
	auto text_section = this->pe->get_section(".text");
	auto new_vec = passes::anti_disassembly::e8ff_decoy(text_section->content(), text_section->virtual_address(), this->funcs); //should be run later when adding other passes
	text_section->content(new_vec);

}

void Obfuscator::build_obfuscated_executable(const std::filesystem::path& out) {
	LIEF::PE::Builder builder(*this->pe);
	builder.build();
	builder.write(out.string());
}
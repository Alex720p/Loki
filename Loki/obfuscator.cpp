#include "obfuscator.hpp"


std::expected<void, std::string> Obfuscator::init_fns_vector() {
	if (!this->pe)
		return std::unexpected("the obfuscator isn't linked to any pe file.");

	auto text_section = this->pe->get_section(".text");
	const auto text = text_section->content();

	PdbParser parser;
	auto parser_result = parser.parse_pdb(this->executable_path);
	if (!parser_result)
		return std::unexpected(parser_result.error());

	auto fns_info_vec = *parser_result;
	for (const auto& fn : fns_info_vec) {
		if (fn.fn_start_addr_rel < text_section->virtual_address() || fn.fn_start_addr_rel + fn.fn_size >= text_section->virtual_address() + text_section->virtual_size())
			return std::unexpected("a function in the pdb file lies outside the bound of .text");

		obfuscator::func_t obfuscator_fn = { .fn_start_addr_rel = fn.fn_start_addr_rel, .fn_size = fn.fn_size };
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

				//TODO: continue here
				offset += instruction.info.length;
			}
			else {
				return std::unexpected(std::format("Zydis failed to decode an instruction at {}", obfuscator_fn.fn_start_addr_rel + offset));
			}
		}
	}
}
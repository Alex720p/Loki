#include "../passes.hpp"

namespace passes::anti_disassembly {
	//not ideal inserting in a vector, but since the .text section shouldn't be too large and there shouldn't be that many decoy spots it shouldn't be that big of an issue
	std::expected<std::vector<uint8_t>, std::string> e8ff_decoy(BinaryFixer& binary_fixer, const std::span<const uint8_t> text, const uint64_t image_base, const uint64_t text_base, std::vector<types::obfuscator::func_t>& funcs, std::vector<ZydisDisassembledInstruction>& outside_fns_rip_jump_stubs) {
		std::vector<uint8_t> new_text(text.begin(), text.end());
		/*int count = 0;
		for (auto& fn : funcs) {
			uint64_t fn_offset = 0;
			uint64_t fn_start_addr_text_rel = fn.fn_start_addr_rel - text_base;
			if (fn.has_jump_table)
				continue;

			for (const auto& instruction : fn.decoded_insts) {
				//TODO: add a field on instructions that tells when they have such a decoy on them, will allow to continue working on obfuscation even after the pass
				uint64_t text_rel_inst_addr = instruction.runtime_address - image_base - text_base;
				if (count < 1) {
					if (new_text[text_rel_inst_addr] == 0xff) {
						auto insertion_it = std::next(new_text.begin(), text_rel_inst_addr);
						new_text.insert(insertion_it, 0xe8);

						uint64_t img_rel_inst_addr = text_rel_inst_addr + text_base;
						binary_fixer.fix_text(new_text, funcs, outside_fns_rip_jump_stubs, img_rel_inst_addr, 1);
						count++;
					}
				}
			}
		}*/


		//TODO: this should be handled in the obfuscator class
		new_text.insert(std::next(new_text.begin(), 0x1fb), 0xe8);
		binary_fixer.fix_text(new_text, funcs, outside_fns_rip_jump_stubs, 0x11fb, 1);
		
		return new_text;
	}
}
#include "../passes.hpp"

namespace passes::anti_disassembly {
	//not ideal inserting in a vector, but since the .text section shouldn't be too large and there shouldn't be that many decoy spots it shouldn't be that big of an issue
	std::expected<std::vector<uint8_t>, std::string> e8ff_decoy(const std::span<const uint8_t> text, const uint64_t image_base, const uint64_t text_base, std::vector<types::obfuscator::func_t>& funcs) {
		std::vector<uint8_t> new_text(text.begin(), text.end());
		uint64_t added_decoys = 0;
		for (auto& fn : funcs) {
			fn.fn_start_addr_rel += added_decoys;
			
			uint64_t previous_added_decoys = added_decoys;
			uint64_t fn_offset = 0;
			uint64_t fn_start_addr_text_rel = fn.fn_start_addr_rel - text_base;
			for (const auto& instruction : fn.decoded_insts) {
				//TODO: add a field on instructions that tells when they have such a decoy on them, will allow to continue working on obfuscation even after the pass
				if (text[fn_start_addr_text_rel + fn_offset] == 0xff) {
					auto insertion_iterator = std::next(new_text.begin(), fn_start_addr_text_rel);
					new_text.insert(std::next(insertion_iterator, fn_offset + added_decoys), 0xe8);
					added_decoys++;

					uint64_t added_bytes_loc = instruction.runtime_address - image_base;
					auto ret = helpers::fix_rip_relative_instructions(new_text, funcs, image_base, text_base, added_bytes_loc, 1);
					if (!ret)
						return std::unexpected(std::format("failed to fix rip relative instructions. {}", ret.error()));
				}
				
				fn_offset += instruction.info.length;
			}

			fn.fn_size += (added_decoys - previous_added_decoys);
		}

		return new_text;
	}
}
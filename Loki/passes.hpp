#pragma once

#include <expected>
#include <vector>
#include <string>
#include <span>
#include "types.hpp"
#include "helpers.hpp"
#include "binary_fixer.hpp"


//each passes should update the funcs struct accordingly
namespace passes {
	namespace transformations {
		std::vector<uint8_t> entrypoint_decoy(BinaryFixer& binary_fixer, const std::span<const uint8_t> text, const uint64_t text_base, std::vector<types::func_t>& funcs);
	}
	//TODO: move this function to its own file
	//void fix_rip_relative_addressing
	namespace anti_disassembly {
		/*
			When an instruction starts with 0xFF, adding an oxE8 byte in front will create an rel jump of dst -1, thus resuming the normal execution of the program.
			However on the disassembly, one will see bogus instructions as the jump will be interpreted before the original instruction
		*/

		//funcs should be sorted by fn rel addresses, the fn will update the fn sizes and rel starting addresses accordingly
		std::vector<uint8_t> ebff_decoy(BinaryFixer& binary_fixer, const std::span<const uint8_t> text, const uint64_t image_base, const uint64_t text_base, std::vector<types::func_t>& funcs, std::vector<ZydisDisassembledInstruction>& outside_fns_rip_jump_stubs);
	}
}
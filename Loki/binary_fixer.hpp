#pragma once

#include "types.hpp"
#include <LIEF/LIEF.hpp>



class BinaryFixer {
private:
	LIEF::PE::Binary* pe;

private:
	bool potential_control_flow_fix_up(const ZydisDisassembledInstruction& inst);
	bool has_rip_explicit_operand(const ZydisDisassembledInstruction& inst);
	void fix_instruction(std::vector<uint8_t>& text, ZydisDisassembledInstruction& inst, const uint64_t img_rel_bytes_added_loc, const uint64_t bytes_added);
public:
	BinaryFixer(LIEF::PE::Binary* pe);
	void fix_text(std::vector<uint8_t>& text, std::vector<types::obfuscator::func_t>& funcs, std::vector<ZydisDisassembledInstruction>& outside_fns_rip_jump_stubs, const uint64_t img_rel_bytes_added_loc, const uint64_t bytes_added);
};
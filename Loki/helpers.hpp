#pragma once
#include <Zydis/Zydis.h>
#include <expected>
#include <string>
#include <vector>
#include "types.hpp"


namespace helpers {

    bool is_inst_control_flow_op(const ZydisDisassembledInstruction& inst);
    bool has_rip_explicit_operand(const ZydisDisassembledInstruction& inst);
    bool control_flow_needs_fix_up(const ZydisDisassembledInstruction& inst);
    //added_bytes_loc is relative to image base
    std::expected<void, std::string> fix_rip_relative_instructions(std::vector<uint8_t>& text, std::vector<types::obfuscator::func_t>& funcs, const uint64_t image_base, const uint64_t text_base, uint64_t added_bytes_loc, uint64_t added_bytes);
}
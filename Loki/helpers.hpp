#pragma once
#include <Zydis/Zydis.h>
#include <expected>
#include <string>
#include <vector>
#include "types.hpp"


namespace helpers {

    bool is_inst_control_flow_op(const ZydisDisassembledInstruction& inst);
    bool has_rip_explicit_operand(const ZydisDisassembledInstruction& inst);
    bool potential_control_flow_fix_up(const ZydisDisassembledInstruction& inst);
    //added_bytes_loc is relative to image base
    void update_structs(std::vector<types::obfuscator::func_t>& funcs, std::vector<ZydisDisassembledInstruction>& outside_fns_rip_jump_stubs, uint64_t bytes_added_loc, uint64_t bytes_added, const uint64_t image_base);
    std::expected<void, std::string> fix_rip_relative_instructions(std::vector<uint8_t>& text, std::vector<types::obfuscator::func_t>& funcs, std::vector<ZydisDisassembledInstruction>& outside_fns_rip_jump_stubs, const uint64_t image_base, const uint64_t text_base, uint64_t img_rel_bytes_added_loc, uint64_t bytes_added);
    std::expected<void, std::string> fix_rip_relative_instructions2(std::vector<uint8_t>& text, ZydisDisassembledInstruction& inst, const uint64_t image_base, const uint64_t text_base, uint64_t img_rel_bytes_added_loc, uint64_t bytes_added);
}
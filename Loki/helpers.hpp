#pragma once
#include <Zydis/Zydis.h>


namespace helpers {

    bool is_inst_control_flow_op(const ZydisDisassembledInstruction& inst);
    bool has_rip_explicit_operand(const ZydisDisassembledInstruction& inst);
}
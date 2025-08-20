#pragma once
#include <Zydis/Zydis.h>
#include "types.hpp"


namespace helpers {
    bool is_inst_control_flow_op(const ZydisDisassembledInstruction& inst);
}
#include "helpers.hpp"


namespace helpers {
    bool is_inst_control_flow_op(const ZydisDisassembledInstruction& inst) {
        switch (inst.info.meta.category)
        {
        case ZYDIS_CATEGORY_COND_BR:
        case ZYDIS_CATEGORY_UNCOND_BR:
        case ZYDIS_CATEGORY_CALL:
        case ZYDIS_CATEGORY_RET:
        case ZYDIS_CATEGORY_INTERRUPT:
        case ZYDIS_CATEGORY_SYSCALL:
        case ZYDIS_CATEGORY_SYSRET:
            return true;
        default:
            return false;
        }
    }
}
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

    bool has_rip_explicit_operand(const ZydisDisassembledInstruction& inst) {
        for (const auto& operand : inst.operands) {
            if (operand.reg.value == ZYDIS_REGISTER_RIP)
                if (operand.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT || operand.visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN)
                    return true;
        }

        return false;
    }
}
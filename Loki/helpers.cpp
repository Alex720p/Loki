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

	bool control_flow_needs_fix_up(const ZydisDisassembledInstruction& inst) {
		if (inst.runtime_address == 0x1400011fb)
			auto tt = 0;

		auto category = inst.info.meta.category;
		if (category != ZYDIS_CATEGORY_COND_BR && category != ZYDIS_CATEGORY_UNCOND_BR && category != ZYDIS_CATEGORY_CALL)
			return false;

		auto operand = inst.operands[0];
		if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
			return true;

		if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
			return operand.mem.base == ZYDIS_REGISTER_RIP;

		return false;
	}

    bool has_rip_explicit_operand(const ZydisDisassembledInstruction& inst) {
        for (const auto& operand : inst.operands) {
            if (operand.reg.value == ZYDIS_REGISTER_RIP)
                if (operand.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
                    return true;
        }

        return false;
    }


	//TODO: FIX UP JUMP TABLE INST
	std::expected<void, std::string> fix_rip_relative_instructions(std::vector<uint8_t>& text, std::vector<types::obfuscator::func_t>& funcs, const uint64_t image_base, const uint64_t text_base, uint64_t added_bytes_loc, uint64_t added_bytes) {
		for (auto& fn : funcs) {
			for (auto& inst : fn.decoded_insts) {
				bool control_flow_needs_fix_up = helpers::control_flow_needs_fix_up(inst);
				bool has_rip_explicit_operand = helpers::has_rip_explicit_operand(inst);
				if (!control_flow_needs_fix_up && !has_rip_explicit_operand) //has_rip_explicit check would suffice
					continue;

				uint64_t abs_addr;
				if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst.info, inst.operands, image_base, &abs_addr)))
					return std::unexpected(std::format("failed to calculate absolute address of jump at instruction {:#x}", inst.runtime_address));

				uint64_t image_rel_addr = abs_addr - image_base;
				if (image_rel_addr < added_bytes_loc)
					continue; //no need for fixing

				//TODO: make sure the offset isn't too big to be encoded
				if (control_flow_needs_fix_up) {
					auto operand = &inst.operands[0];
					if (operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
						if (operand->imm.is_signed)
							operand->imm.value.s += added_bytes;
						else
							operand->imm.value.u += added_bytes;
					}
					else if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY) {
						operand->mem.disp.has_displacement = true;
						operand->mem.disp.value += added_bytes;
					}
					else {
						return std::unexpected(std::format("unhandled behavior encountered: a control flow op needing fix up couldn't be fixed at {:#x}", inst.runtime_address)); //unless we change helpers::control_flow_needs_fix_up, will never reach here
					}

				}
				else if (has_rip_explicit_operand) {
					for (auto& operand : inst.operands) {
						if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == ZYDIS_REGISTER_RIP) {
							operand.mem.disp.has_displacement = true;
							operand.mem.disp.value += added_bytes;
						}
					}
				}


				ZydisEncoderRequest enc_req;
				if (!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(&inst.info, inst.operands, inst.info.operand_count_visible, &enc_req)))
					return std::unexpected(std::format("failed to create encoder request for instruction at {:#x}", inst.runtime_address));

				uint8_t new_encoded_inst[ZYDIS_MAX_INSTRUCTION_LENGTH];
				ZyanUSize new_encoded_inst_length = sizeof(new_encoded_inst);
				if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&enc_req, new_encoded_inst, &new_encoded_inst_length)))
					return std::unexpected(std::format("failed to create encoder request for instruction at {:#x}", inst.runtime_address));

				//seems like there is no way to make the encoder encode the 0x48 prefix (some prefix are supported but not this one)
				if (inst.info.raw.prefix_count) {
					if (inst.info.raw.prefixes[0].value == 0x48) {
						if (new_encoded_inst_length < ZYDIS_MAX_INSTRUCTION_LENGTH) {
							std::memmove(new_encoded_inst + 1, new_encoded_inst, new_encoded_inst_length);
							new_encoded_inst[0] = 0x48;
							new_encoded_inst_length++;
						}
						else {
							return std::unexpected(std::format("failed to reencode the 0x48 prefix at {:#x}", inst.runtime_address));
						}
					}

				}

				//TODO: CHECK IF ZYDIS AUTOMATICALLY SIZES UP IF OVERFLOW IN JUMP LENGTH
				if (new_encoded_inst_length != inst.info.length)
					return std::unexpected(std::format("unhandled behavior, reencoded instruction at {:#x} is larger than the original instruction", inst.runtime_address));

				uint64_t text_rel_inst_pos = inst.runtime_address - image_base - text_base;
				auto vector_replace_pos_it = std::next(text.begin(), text_rel_inst_pos);
				std::copy(new_encoded_inst, new_encoded_inst + new_encoded_inst_length, vector_replace_pos_it);
			}
		}

		//TODO: also traverse stubs
	}
}
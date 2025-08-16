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

	bool potential_control_flow_fix_up(const ZydisDisassembledInstruction& inst) {
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

	//TODO: rework this one
    bool has_rip_explicit_operand(const ZydisDisassembledInstruction& inst) {
        for (const auto& operand : inst.operands) {
            if (operand.reg.value == ZYDIS_REGISTER_RIP)
                if (operand.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
                    return true;
        }

        return false;
    }

	void update_structs(std::vector<types::obfuscator::func_t>& funcs, std::vector<ZydisDisassembledInstruction>& outside_fns_rip_jump_stubs, uint64_t img_rel_bytes_added_loc, uint64_t bytes_added, const uint64_t image_base) {
		for (auto& fn : funcs) {
			if (img_rel_bytes_added_loc > fn.fn_start_addr_rel)
				continue; //no need to update fn or instructions

			if (img_rel_bytes_added_loc >= fn.fn_start_addr_rel && img_rel_bytes_added_loc < fn.fn_start_addr_rel + fn.fn_size)
				fn.fn_size += bytes_added;

			if (img_rel_bytes_added_loc < fn.fn_start_addr_rel)
				fn.fn_start_addr_rel += bytes_added;

			for (auto& inst : fn.decoded_insts)
				if (img_rel_bytes_added_loc <= inst.runtime_address - image_base)
					inst.runtime_address += bytes_added;

		 }

		for (auto& stub : outside_fns_rip_jump_stubs) {
			uint64_t img_rel_stub_addr = stub.runtime_address - image_base;
			if (img_rel_bytes_added_loc > img_rel_stub_addr)
				continue; //no need to update fn or instructions

			stub.runtime_address += bytes_added;
		}
	}

	std::expected<void, std::string> fix_rip_relative_instructions2(std::vector<uint8_t>& text, ZydisDisassembledInstruction& inst, const uint64_t image_base, const uint64_t text_base, uint64_t img_rel_bytes_added_loc, uint64_t bytes_added) {
		bool potential_control_flow_fix_up = helpers::potential_control_flow_fix_up(inst);
		bool has_rip_explicit_operand = helpers::has_rip_explicit_operand(inst);
		if (!potential_control_flow_fix_up && !has_rip_explicit_operand) //has_rip_explicit check would suffice
			return {};

		uint64_t dst_addr;
		if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst.info, inst.operands, inst.runtime_address, &dst_addr)))
			return std::unexpected(std::format("failed to calculate absolute address of jump at instruction {:#x}", inst.runtime_address));

		uint64_t img_rel_dst_addr = dst_addr - image_base;
		//TODO: make sure the offset isn't too big to be encoded
		if (potential_control_flow_fix_up) {
			uint64_t img_rel_inst_addr = inst.runtime_address - image_base;
			auto operand = &inst.operands[0];

			//we can jump backwards or forwards, need to distinguish the min and max 
			uint64_t max = std::max(img_rel_dst_addr, img_rel_inst_addr);
			uint64_t min = std::min(img_rel_dst_addr, img_rel_inst_addr);

			
			/*if (operand->imm.is_relative) {
			}
			//img_rel_inst_addr < img_rel_bytes_added_loc && img_rel_bytes_added_loc <= img_rel_dst_addr
			else { //TODO: review this
				if (img_rel_inst_addr < img_rel_dst_addr) {
					if (img_rel_inst_addr >= img_rel_bytes_added_loc || img_rel_bytes_added_loc > img_rel_dst_addr)
						return {};
				}
				else {

				}
				
			}*/

			if (img_rel_bytes_added_loc <= min || img_rel_bytes_added_loc > max)
				return {};

			

			if (operand->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				if (operand->imm.is_signed)
					operand->imm.value.s += bytes_added * (img_rel_dst_addr != max ? -1 : 1);
				else
					operand->imm.value.u += bytes_added; //no need to adjust sign here since adding bytes will never have us changing the value to signed
			}
			else if (operand->type == ZYDIS_OPERAND_TYPE_MEMORY) {
				//TODO: need to check in which section this points, if the added bytes doesn't resize the physical size of .text section and it points outside, no need to relocate
				operand->mem.disp.has_displacement = true; //I don't see why this wouldn't be already true but setting it again doesn't hurt
				operand->mem.disp.value += bytes_added * (img_rel_dst_addr != max ? -1 : 1);
			}
			else {
				return std::unexpected(std::format("unhandled behavior encountered: a control flow op needing fix up couldn't be fixed at {:#x}", inst.runtime_address)); //unless we change helpers::control_flow_needs_fix_up, will never reach here
			}

		}
		else if (has_rip_explicit_operand) {
			//TODO: same here with section checks
			for (auto& operand : inst.operands) {
				if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == ZYDIS_REGISTER_RIP) {
					operand.mem.disp.has_displacement = true;
					operand.mem.disp.value += bytes_added;
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

	//TODO: FIX THE ENTRY POINT ADDRESS
	//TODO: FIX UP JUMP TABLE INST
	std::expected<void, std::string> fix_rip_relative_instructions(std::vector<uint8_t>& text, std::vector<types::obfuscator::func_t>& funcs, std::vector<ZydisDisassembledInstruction>& outside_fns_rip_jump_stubs, const uint64_t image_base, const uint64_t text_base, uint64_t img_rel_bytes_added_loc, uint64_t bytes_added) {
		for (auto& fn : funcs) {
			for (auto& inst : fn.decoded_insts) {
				helpers::fix_rip_relative_instructions2(text, inst, image_base, text_base, img_rel_bytes_added_loc, bytes_added);
			}
		}

		for (auto& inst : outside_fns_rip_jump_stubs) {
			helpers::fix_rip_relative_instructions2(text, inst, image_base, text_base, img_rel_bytes_added_loc, bytes_added);
		}

		return {};
	}
}
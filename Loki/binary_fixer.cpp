#include "binary_fixer.hpp"


BinaryFixer::BinaryFixer(LIEF::PE::Binary* pe) {
	if (!pe)
		throw std::runtime_error("Can't initialize the BinaryFixer class with an empty pe ptr");

	this->pe = pe;
}

void BinaryFixer::fix_instruction(std::vector<uint8_t>& text, types::instruction_wrapper_t& inst_wrapper, const uint64_t old_img_rel_inst_addr, const uint64_t img_rel_bytes_added_loc, const uint64_t bytes_added) {
	if (!inst_wrapper.control_flow_might_need_fix && !inst_wrapper.needs_explicit_operand_fix())
		return;
	
	uint8_t effective_operand_index = inst_wrapper.control_flow_might_need_fix ? 0 : inst_wrapper.explicit_rip_operand_index;
	uint64_t dst_addr;
	if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&inst_wrapper.inst.info, &inst_wrapper.inst.operands[effective_operand_index], old_img_rel_inst_addr + pe->imagebase(), &dst_addr)))
		throw std::runtime_error(std::format("Failed to calculate absolute address of jump at instruction {:#x}", old_img_rel_inst_addr));

	uint64_t old_img_rel_dst_addr = dst_addr - pe->imagebase();

	uint64_t new_img_rel_inst_addr = inst_wrapper.inst.runtime_address - pe->imagebase();
	auto& operand = inst_wrapper.inst.operands[effective_operand_index];
	if (!inst_wrapper.references_outside_of_dot_text) {
		//TODO: check that the added bytes don't cause the .text section to be resized

		//TODO: make sure the offset isn't too big to be encoded

		//we can jump backwards or forwards, need to distinguish the min and max 
		uint64_t max = std::max(old_img_rel_inst_addr, old_img_rel_dst_addr);
		uint64_t min = std::min(old_img_rel_inst_addr, old_img_rel_dst_addr);

		if (img_rel_bytes_added_loc <= min || img_rel_bytes_added_loc > max)
			return;

		if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			if (operand.imm.is_signed)
				operand.imm.value.s += bytes_added * (old_img_rel_inst_addr == max ? -1 : 1);
			else
				operand.imm.value.u += bytes_added; //no need to adjust sign here since adding bytes will never have us changing the value to signed
		}
		else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
			operand.mem.disp.has_displacement = true; //should already be set to true
			operand.mem.disp.value += bytes_added * (old_img_rel_inst_addr == max ? -1 : 1);
		}
		else {
			throw std::runtime_error(std::format("unhandled behavior encountered: a control flow op needing fix up couldn't be fixed at {:#x}", old_img_rel_inst_addr)); //unless we change helpers::control_flow_needs_fix_up, will never reach here
		}

	} else { //not in .text
		if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY) //I'm pretty sure this will never happen
			throw std::runtime_error(std::format("unhandled behavior encountered: a control flow op leading outside of .text doesn't have a supported operand type be fixed at {:#x}", old_img_rel_inst_addr)); //unless we change helpers::control_flow_needs_fix_up, will never reach here

		if (img_rel_bytes_added_loc <= old_img_rel_inst_addr)
			operand.mem.disp.value -= bytes_added;
	}

	ZydisEncoderRequest enc_req;
	if (!ZYAN_SUCCESS(ZydisEncoderDecodedInstructionToEncoderRequest(&inst_wrapper.inst.info, inst_wrapper.inst.operands, inst_wrapper.inst.info.operand_count_visible, &enc_req)))
		throw std::runtime_error(std::format("failed to create encoder request for instruction at {:#x}", old_img_rel_inst_addr));

	uint8_t new_encoded_inst[ZYDIS_MAX_INSTRUCTION_LENGTH];
	ZyanUSize new_encoded_inst_length = sizeof(new_encoded_inst);
	if (!ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&enc_req, new_encoded_inst, &new_encoded_inst_length)))
		throw std::runtime_error(std::format("failed to create encoder request for instruction at {:#x}", old_img_rel_inst_addr));

	//sometimes the encoder doesn't encode correctly the 0x48 prefix
	if (inst_wrapper.inst.info.raw.prefix_count) {
		if (inst_wrapper.inst.info.raw.prefixes[0].value == 0x48 && new_encoded_inst[0] != 0x48) {
			if (new_encoded_inst_length < ZYDIS_MAX_INSTRUCTION_LENGTH) {
				std::memmove(new_encoded_inst + 1, new_encoded_inst, new_encoded_inst_length);
				new_encoded_inst[0] = 0x48;
				new_encoded_inst_length++;
			}
			else {
				throw std::runtime_error(std::format("failed to reencode the 0x48 prefix at {:#x}", old_img_rel_inst_addr));
			}
		}

	}

	//TODO: CHECK IF ZYDIS AUTOMATICALLY SIZES UP IF OVERFLOW IN JUMP LENGTH
	if (new_encoded_inst_length != inst_wrapper.inst.info.length)
		throw std::runtime_error(std::format("unhandled behavior, reencoded instruction at {:#x} is larger than the original instruction", old_img_rel_inst_addr));

	uint64_t new_text_rel_inst_pos = new_img_rel_inst_addr - pe->get_section(".text")->virtual_address();
	auto vector_replace_pos_it = std::next(text.begin(), new_text_rel_inst_pos);
	std::copy(new_encoded_inst, new_encoded_inst + new_encoded_inst_length, vector_replace_pos_it);
}

void BinaryFixer::fix_text(std::vector<uint8_t>& text, std::vector<types::func_t>& funcs, std::vector<types::instruction_wrapper_t>& outside_fns_rip_jump_stubs, const uint64_t img_rel_bytes_added_loc, const uint64_t bytes_added) {
	for (auto& fn : funcs) {
		if (img_rel_bytes_added_loc >= fn.img_rel_start_addr && img_rel_bytes_added_loc < fn.img_rel_start_addr + fn.fn_size)
			fn.fn_size += bytes_added;

		if (img_rel_bytes_added_loc < fn.img_rel_start_addr)
			fn.img_rel_start_addr += bytes_added;

		for (auto& inst_wrapper : fn.decoded_insts_wrappers) {
			uint64_t old_img_rel_inst_addr = inst_wrapper.inst.runtime_address - this->pe->imagebase();
			if (img_rel_bytes_added_loc <= old_img_rel_inst_addr)
				inst_wrapper.inst.runtime_address += bytes_added;

			this->fix_instruction(text, inst_wrapper, old_img_rel_inst_addr, img_rel_bytes_added_loc, bytes_added);
		}
	}

	for (auto& inst_wrapper : outside_fns_rip_jump_stubs) {
		uint64_t old_img_rel_stub_addr = inst_wrapper.inst.runtime_address - this->pe->imagebase();
		if (img_rel_bytes_added_loc <= old_img_rel_stub_addr)
			inst_wrapper.inst.runtime_address += bytes_added;


		this->fix_instruction(text, inst_wrapper, old_img_rel_stub_addr, img_rel_bytes_added_loc, bytes_added);
	}
}

void BinaryFixer::fix_crt_entries(const std::vector<types::func_t>& funcs) {
	for (const auto& fn : funcs) {
		if (!fn.crt_entry)
			continue;

		this->pe->patch_address(fn.crt_entry, fn.img_rel_start_addr + this->pe->imagebase());
	}
}

bool BinaryFixer::fix_entrypoint_addr(const  std::vector<types::func_t>& funcs) {
	for (const auto& fn : funcs) {
		if (fn.is_entry_point) {
			this->pe->optional_header().addressof_entrypoint(fn.img_rel_start_addr);
			return true;
		}
	}
	return false;
}

void BinaryFixer::handle_text_section_resize(std::vector<uint8_t>& text, std::vector<types::func_t>& funcs, std::vector<types::instruction_wrapper_t>& outside_fns_rip_jump_stubs, const uint64_t old_virtual_text_size, const uint64_t new_virtual_text_size) {
	auto section_alignment = this->pe->optional_header().file_alignment();
	uint64_t old_size_mapped = ((old_virtual_text_size + (section_alignment - 1)) / section_alignment) + 1; //rounding up to a multiple of 0x1000
	uint64_t new_size_mapped = ((new_virtual_text_size + (section_alignment - 1)) / section_alignment) + 1;
	if (old_size_mapped == new_size_mapped)
		return; //no changes to be made

	uint64_t diff_section_size = new_size_mapped - old_size_mapped;
	for (auto& fn : funcs) {
		for (auto& inst_wrapper : fn.decoded_insts_wrappers) {
			if (!inst_wrapper.references_outside_of_dot_text)
				continue;

			this->fix_instruction(text, inst_wrapper, inst_wrapper.inst.runtime_address - pe->imagebase(), this->pe->get_section(".text")->virtual_address() + new_virtual_text_size, diff_section_size);
		}
	}

	for (auto& inst_wrapper : outside_fns_rip_jump_stubs) {
		if (!inst_wrapper.references_outside_of_dot_text)
			continue;

		this->fix_instruction(text, inst_wrapper, inst_wrapper.inst.runtime_address - pe->imagebase(), this->pe->get_section(".text")->virtual_address() + new_virtual_text_size, diff_section_size);
	}
}
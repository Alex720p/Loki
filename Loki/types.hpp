#pragma once

#include <iostream>
#include <vector>
#include <Zydis/Zydis.h>

#define EXPLICIT_RIP_OPERAND_NO_FIX_INDEX -1

namespace types {
	struct instruction_wrapper_t {
		ZydisDisassembledInstruction inst = {};
		bool control_flow_might_need_fix = false;
		int8_t explicit_rip_operand_index = EXPLICIT_RIP_OPERAND_NO_FIX_INDEX; //-1 means no fixing needed
		bool references_outside_of_dot_text = false; // could be a call qword ptr [<some addr in .data>] for ex

		bool needs_explicit_operand_fix() { return this->explicit_rip_operand_index != EXPLICIT_RIP_OPERAND_NO_FIX_INDEX; }
	};

	struct func_t {
		std::vector<instruction_wrapper_t> decoded_insts_wrappers = {}; //ordered by the order they appear in the fn
		size_t img_rel_start_addr; //relative to where image is loaded
		uint32_t fn_size;
		bool has_jump_table = false;
		bool is_entry_point = false;
		uint64_t crt_entry = 0; //0 means no entry

		bool operator<(const func_t& other) const {
			return this->img_rel_start_addr < other.img_rel_start_addr;
		}
	};

}

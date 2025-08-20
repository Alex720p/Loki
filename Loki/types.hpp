#pragma once

#include <iostream>
#include <vector>
#include <Zydis/Zydis.h>

namespace types {
	struct func_t {
		std::vector<ZydisDisassembledInstruction> decoded_insts = {}; //ordered by the order they appear in the fn
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

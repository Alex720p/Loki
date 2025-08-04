#pragma once


#include <iostream>
#include <list>
#include <Zydis/Zydis.h>

namespace types {
	namespace obfuscator {
		struct func_t {
			size_t fn_start_addr_rel; //relative to where image is loaded
			uint32_t fn_size;
			bool has_jump_table = false;
			std::list<ZydisDisassembledInstruction> decoded_insts = {}; //ordered by the order they appear in the fn

			bool operator<(const func_t& other) const {
				return this->fn_start_addr_rel < other.fn_start_addr_rel;
			}
		};
	}
}

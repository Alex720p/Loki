#pragma once

#include "types.hpp"
#include <LIEF/LIEF.hpp>



class BinaryFixer {
private:
	LIEF::PE::Binary* pe;

private:
	void fix_instruction(std::vector<uint8_t>& text, types::instruction_wrapper_t& inst_wrapper, const uint64_t old_img_rel_inst_addr, const uint64_t img_rel_bytes_added_loc, const uint64_t bytes_added);
public:
	BinaryFixer(LIEF::PE::Binary* pe);
	void fix_text(std::vector<uint8_t>& text, std::vector<types::func_t>& funcs, std::vector<types::instruction_wrapper_t>& outside_fns_rip_jump_stubs, const uint64_t img_rel_bytes_added_loc, const uint64_t bytes_added);
	void fix_crt_entries(const std::vector<types::func_t>& funcs);
	void handle_text_section_resize(std::vector<uint8_t>& text, std::vector<types::func_t>& funcs, std::vector<types::instruction_wrapper_t>& outside_fns_rip_jump_stubs, const uint64_t old_virtual_text_size, const uint64_t new_virtual_text_size, const uint64_t old_raw_text_size, const uint64_t new_raw_text_size);
	bool fix_entrypoint_addr(const  std::vector<types::func_t>& funcs);
};
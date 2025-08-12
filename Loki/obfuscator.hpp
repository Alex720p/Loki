#pragma once

#include <LIEF/LIEF.hpp>
#include <Zydis/Zydis.h>
#include "pdb_parser.hpp"
#include "passes.hpp"
#include "types.hpp"
#include "helpers.hpp"


//note: when inserting stuff, always consider the case that we're inserting to the left of an element
class Obfuscator {
private:
	std::unique_ptr<LIEF::PE::Binary> pe;
	std::vector<types::obfuscator::func_t> funcs = {}; //sorted by fn_start_addr_rel from smallest to biggest
	std::vector<ZydisDisassembledInstruction> outside_fns_rip_jump_stubs = {}; //not sorted, the runtime address (pe->imagebase() is added in the instructions runtime addr)
	bool is_funcs_valid = false; //some passes like the e8ff will make the funcs var not up-to-date anymore, this keeps track of it
private:
	std::expected<void, std::string> init_fns(const std::filesystem::path& executable_path);
public:
	void init(const std::filesystem::path& executable_path);
	void run_passes();
	std::expected<void, std::string> fix_rip_relative_instructions(std::vector<uint8_t>& text, const uint64_t image_base, const uint64_t text_base, uint64_t added_bytes_loc, uint64_t added_bytes); //added bytes loc should be relative to image base
	void build_obfuscated_executable(const std::filesystem::path& out);
};
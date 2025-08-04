#pragma once

#include <LIEF/LIEF.hpp>
#include <Zydis/Zydis.h>
#include "pdb_parser.hpp"
#include "passes.hpp"
#include "types.hpp"
#include "helpers.hpp"


class Obfuscator {
private:
	std::unique_ptr<LIEF::PE::Binary> pe;
	std::vector<types::obfuscator::func_t> funcs = {}; //sorted by fn_start_addr_rel from smallest to biggest
	std::vector<uint64_t> rel_addr_of_jump_outsides_funcs = {}; //not sorted
	bool is_funcs_valid = false; //some passes like the e8ff will make the funcs var not up-to-date anymore, this keeps track of it
private:
	std::expected<void, std::string> init_fns(const std::filesystem::path& executable_path);
public:
	void init(const std::filesystem::path& executable_path);
	void run_passes();
	void build_obfuscated_executable(const std::filesystem::path& out);
};
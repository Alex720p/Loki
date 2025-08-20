#pragma once

#include <LIEF/LIEF.hpp>
#include <Zydis/Zydis.h>
#include "pdb_parser.hpp"
#include "passes.hpp"
#include "types.hpp"
#include "helpers.hpp"
#include "binary_fixer.hpp"


//note: when inserting stuff, always consider the case that we're inserting to the left of an element
class Obfuscator {
private:
	std::unique_ptr<LIEF::PE::Binary> pe;
	BinaryFixer binary_fixer;
	std::vector<types::func_t> funcs = {}; //sorted by img_rel_start_addr from smallest to biggest
	std::vector<types::instruction_wrapper_t> outside_fns_rip_jump_stubs = {}; //not sorted, the runtime address (pe->imagebase() is added in the instructions runtime addr)
private:
	bool does_fn_contain_jump_table(const ZydisDisassembledInstruction& inst, const uint64_t image_base);
	bool potential_control_flow_fix_up(const ZydisDisassembledInstruction& inst);
	int8_t get_rip_explicit_operand_index(const ZydisDisassembledInstruction& inst);
	void init_fns(const std::filesystem::path& executable_path);
	uint64_t get_fn_entry_addr(const uint64_t img_rel_fn_start_addr, const uint64_t img_rel_start, const uint64_t img_rel_end);
public:
	Obfuscator(const std::filesystem::path& executable_path);
	void run_passes();
	void build_executable(const std::filesystem::path& out);
};
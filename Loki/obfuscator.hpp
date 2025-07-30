#include <LIEF/LIEF.hpp>
#include <Zydis/Zydis.h>
#include "pdb_parser.hpp"


namespace obfuscator {
	struct func_t {
		size_t fn_start_addr_rel; //relative to where image is loaded
		uint32_t fn_size;
		bool has_jump_table = false;
		std::list<ZydisDecodedInstruction> decoded_insts = {};
	};
}

class Obfuscator {
private:
	std::filesystem::path executable_path;
	std::unique_ptr<LIEF::PE::Binary> pe;
	std::vector<obfuscator::func_t> funcs = {};
private:
	std::expected<void, std::string> init_fns_vector();
public:

};
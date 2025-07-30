#include "pdb_parser.hpp"

#include <DbgHelp.h>


#define DUMMY_BASE_DLL 0x1000 //need to have something else than 0, value doesn't matter. Maybe there's a better way but this works

static BOOL CALLBACK enum_symbols_callback(PSYMBOL_INFO psym_info, ULONG symbol_size, PVOID pfn_info_vec) {
	if (!pfn_info_vec)
		return FALSE;

	std::vector<fn_info_t>* fn_info_vec = reinterpret_cast<std::vector<fn_info_t>*>(pfn_info_vec);
	if (psym_info->Tag == SymTagFunction) {
		fn_info_t fn_info = { 0 };
		fn_info.fn_start_addr_raw = psym_info->Address - DUMMY_BASE_DLL;
		fn_info.fn_size = psym_info->Size;

		fn_info_vec->push_back(fn_info);
	}

	return TRUE; //makes the enumeration continue
}


PdbParser::PdbParser(const std::filesystem::path& executable_path) {
	if (!SymInitialize(GetCurrentProcess(), executable_path.parent_path().string().c_str(), false))
		throw std::runtime_error("Failed to initialize the symbol handler.");

	if (!SymLoadModuleEx(GetCurrentProcess(), NULL, executable_path.string().c_str(), NULL, DUMMY_BASE_DLL, NULL, NULL, NULL))
		throw std::runtime_error("Failed to load the symbol table.");

	if (!SymEnumSymbols(GetCurrentProcess(), DUMMY_BASE_DLL, "*", enum_symbols_callback, &this->fn_info_vec))
		throw std::runtime_error("Failed to enumerate symbols.");

}

std::vector<fn_info_t> PdbParser::get_fn_info() { return this->fn_info_vec;  }
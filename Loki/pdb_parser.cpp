#include "pdb_parser.hpp"
#include <DbgHelp.h>

#define DUMMY_BASE_DLL 0x1000 //need to have something else than 0, value doesn't matter. Maybe there's a better way but this works

static BOOL CALLBACK enum_symbols_callback(PSYMBOL_INFO psym_info, ULONG symbol_size, PVOID pfn_info_vec) {
	if (!pfn_info_vec)
		return FALSE;

	std::vector<pdb_parser::fn_info_t>* fn_info_vec = reinterpret_cast<std::vector<pdb_parser::fn_info_t>*>(pfn_info_vec);
	if (psym_info->Tag == SymTagFunction) {
		pdb_parser::fn_info_t fn_info = { 0 };
		fn_info.fn_start_addr_rel = psym_info->Address - DUMMY_BASE_DLL;
		fn_info.fn_size = psym_info->Size;

		fn_info_vec->push_back(fn_info);
	}

	return TRUE; //makes the enumeration continue
}


std::expected<std::vector<pdb_parser::fn_info_t>, std::string> PdbParser::parse_pdb(const std::filesystem::path executable_path) {
	std::vector<pdb_parser::fn_info_t> fn_info_vec = {};
	if (!SymInitialize(GetCurrentProcess(), executable_path.parent_path().string().c_str(), false))
		return std::unexpected("failed to initialize the symbol handler.");

	if (!SymLoadModuleEx(GetCurrentProcess(), NULL, executable_path.string().c_str(), NULL, DUMMY_BASE_DLL, NULL, NULL, NULL))
		throw std::unexpected("failed to load the symbol table.");

	if (!SymEnumSymbols(GetCurrentProcess(), DUMMY_BASE_DLL, "*", enum_symbols_callback, &fn_info_vec))
		throw std::unexpected("failed to enumerate symbols.");

	return fn_info_vec;
}
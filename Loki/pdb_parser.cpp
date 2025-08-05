#include "pdb_parser.hpp"
#include <DbgHelp.h>

#define DUMMY_BASE 0x1000 //need to have something else than 0, value doesn't matter. Maybe there's a better way but this works


static BOOL CALLBACK enum_symbols_callback(PSYMBOL_INFO psym_info, ULONG symbol_size, PVOID user_context) {
	if (!user_context)
		return FALSE;

	pdb_parser::user_ctx* ctx = reinterpret_cast<pdb_parser::user_ctx*>(user_context);

	if (psym_info->Tag == SymTagFunction) {
		pdb_parser::fn_info_t fn_info = { 0 };
		fn_info.fn_start_addr_rel = psym_info->Address - DUMMY_BASE;
		fn_info.fn_size = psym_info->Size;

		ctx->fn_info_vec.push_back(fn_info);
	}
	else if (psym_info->Tag == SymTagPublicSymbol || psym_info->Tag == SymTagData) { //SymTagPublicSymbols for imports jump stubs (ex: memcpy...) and SymTagData for control flow guard jumps etc...
		uint64_t symbol_addr_without_base = psym_info->Address - DUMMY_BASE;
		if (symbol_addr_without_base >= ctx->dot_text_base && symbol_addr_without_base < ctx->dot_text_base + ctx->dot_text_size)
			ctx->potential_jump_stubs.push_back(psym_info->Address - DUMMY_BASE); //if outside of .text section don't care
	}

	return TRUE; //makes the enumeration continue
}


std::expected<pdb_parser::user_ctx, std::string> PdbParser::parse_pdb(const std::filesystem::path executable_path, const uint64_t text_base, const uint64_t text_size) {
	pdb_parser::user_ctx ctx = {.dot_text_base = text_base, .dot_text_size = text_size};
	if (!SymInitialize(GetCurrentProcess(), executable_path.parent_path().string().c_str(), false))
		return std::unexpected("failed to initialize the symbol handler.");

	if (!SymLoadModuleEx(GetCurrentProcess(), NULL, executable_path.string().c_str(), NULL, DUMMY_BASE, NULL, NULL, NULL))
		throw std::unexpected("failed to load the symbol table.");

	if (!SymEnumSymbols(GetCurrentProcess(), DUMMY_BASE, "*", enum_symbols_callback, &ctx))
		throw std::unexpected("failed to enumerate symbols.");

	return ctx;
}
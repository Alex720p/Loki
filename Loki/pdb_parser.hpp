#pragma once

#include <Windows.h>
#include <string_view>
#include <stdexcept>
#include <filesystem>
#include <expected>

enum SymTagEnum {
    SymTagNull,
    SymTagExe,
    SymTagCompiland,
    SymTagCompilandDetails,
    SymTagCompilandEnv,
    SymTagFunction,
    SymTagBlock,
    SymTagData,
    SymTagAnnotation,
    SymTagLabel,
    SymTagPublicSymbol,
    SymTagUDT,
    SymTagEnum,
    SymTagFunctionType,
    SymTagPointerType,
    SymTagArrayType,
    SymTagBaseType,
    SymTagTypedef,
    SymTagBaseClass,
    SymTagFriend,
    SymTagFunctionArgType,
    SymTagFuncDebugStart,
    SymTagFuncDebugEnd,
    SymTagUsingNamespace,
    SymTagVTableShape,
    SymTagVTable,
    SymTagCustom,
    SymTagThunk,
    SymTagCustomType,
    SymTagManagedType,
    SymTagDimension,
    SymTagCallSite,
    SymTagInlineSite,
    SymTagBaseInterface,
    SymTagVectorType,
    SymTagMatrixType,
    SymTagHLSLType,
    SymTagCaller,
    SymTagCallee,
    SymTagExport,
    SymTagHeapAllocationSite,
    SymTagCoffGroup,
    SymTagInlinee,
    SymTagTaggedUnionCase,
};


#pragma comment(lib, "dbghelp.lib")


namespace pdb_parser {
    struct fn_info_t {
        ULONG64 fn_start_addr_rel; //relative to where image is loaded
        ULONG fn_size;
    };

    struct user_ctx {
        std::vector<pdb_parser::fn_info_t> fn_info_vec = {};
        std::vector<uint64_t> potential_jump_stubs = {};
        uint64_t dot_text_base;
        uint64_t dot_text_size;
    };
}

class PdbParser {
public:
    std::expected<pdb_parser::user_ctx, std::string> parse_pdb(const std::filesystem::path executable_path, const uint64_t text_base, const uint64_t text_size);
};
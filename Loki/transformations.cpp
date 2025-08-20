#include "passes.hpp"

namespace passes::transformations {
	std::vector<uint8_t> entrypoint_decoy(BinaryFixer& binary_fixer, const std::span<const uint8_t> text, const uint64_t text_base, std::vector<types::obfuscator::func_t>& funcs) {
		return {};
	}
}
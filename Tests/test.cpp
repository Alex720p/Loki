#include "gtest/gtest.h"
#include "../Loki/helpers.hpp"
#include "../Loki/obfuscator.hpp"


TEST(relocations, relative_jumps_are_fixed_correctly) {
	const unsigned char instructions[] = {
	  0x48, 0x8B, 0x01,       // mov rax, [rcx]
	  0x48, 0x63, 0x48, 0x04,    // movsxd  rax, dword ptr [rax+0x4]
	  0x48, 0x8B, 0x7C, 0x31, 0x28, // mov rdi, [rcx+rsi*1+0x28]
	  0x48, 0x85, 0xFF,       // test rdi, rdi
	  0x7E, 0x03,             // jle 0xaddress
	  0x48, 0x85, 0xFF        // test rdi, rdi
	};

	uint64_t dummy_image_base = 0x140000000;
	uint64_t dummy_text_base = 0x1000;
	uint64_t dummy_fn_start_addr = 0;
	uint32_t dummy_fn_size = sizeof(instructions);
	types::obfuscator::func_t dummy_fn = { .fn_start_addr_rel = dummy_text_base + dummy_fn_start_addr, .fn_size = dummy_fn_size };

	uint64_t offset = 0;
	ZydisDisassembledInstruction instruction;
	uint64_t runtime_addr = dummy_image_base + dummy_text_base + dummy_fn_start_addr;
	while (ZYAN_SUCCESS(ZydisDisassembleIntel(
		/* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
		/* runtime_address: */ runtime_addr + offset,
		/* buffer:          */ instructions + offset,
		/* length:          */ dummy_fn_size - offset,
		/* instruction:     */ &instruction
	))) {
		dummy_fn.decoded_insts.push_back(instruction);
		offset += instruction.info.length;
	}

	std::vector<types::obfuscator::func_t> dummy_fns = { dummy_fn };
	std::vector<uint8_t> fake_text(instructions, instructions + sizeof(instructions));
	uint64_t added_bytes = 4;
	auto ret = helpers::fix_rip_relative_instructions(fake_text, dummy_fns, dummy_image_base, dummy_text_base, dummy_text_base + dummy_fn_start_addr + 17, added_bytes);

	EXPECT_EQ(fake_text[16], instructions[16] + added_bytes);
}
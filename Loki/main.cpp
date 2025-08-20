#include "obfuscator.hpp"
#include <iostream>

int main() {
	const std::filesystem::path path = R"(C:\Users\alexa\source\repos\jump_table\x64\Release\jump_table.exe)";
	Obfuscator obfuscator(path);
	obfuscator.run_passes();
	obfuscator.build_executable(R"(C:\Users\alexa\source\repos\jump_table\x64\Release\obf.exe)");
	

	/*const std::filesystem::path path = R"(C:\Users\alexa\source\repos\message_box\x64\Release\message_box.dll)";
	Obfuscator obfuscator(path);
	obfuscator.run_passes();
	obfuscator.build_executable(R"(C:\Users\alexa\source\repos\message_box\x64\Release\message_box_obf.dll)");*/

#if 0
	//unsigned char inst[] = { 0xE9, 0x72, 0xFE, 0xFF, 0xFF };
	//unsigned char inst[] = { 0xE8, 0xC7, 0x03, 0x00, 0x00 };
	//unsigned char inst[] = { 0x48, 0x8D, 0x15, 0xBE, 0xEF, 0xFF, 0xFF };
	//unsigned char inst[] = { 0x48, 0x83, 0xEC, 0x20 };
	unsigned char inst[] = { 0xFF, 0x15, 0x53, 0x1F, 0x00, 0x00 };
	auto pe = LIEF::PE::Parser::parse(path.string());
	ZydisDisassembledInstruction instruction;
	auto text_section = pe->get_section(".text");
	auto text = text_section->content();
	ZydisDisassembleIntel(
		/* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
		/* runtime_address: */ pe->imagebase() + 0x16bd,
		/* buffer:          */ inst,
		/* length:          */ sizeof(inst),
		/* instruction:     */ &instruction);
#endif
	return 0;
}
#include "obfuscator.hpp"
#include <iostream>

int main() {
	//dbParser parser(");
	const std::filesystem::path path = R"(C:\Users\alexa\source\repos\jump_table\x64\Release\jump_table.exe)";
	Obfuscator obfuscator;
	obfuscator.init(path);

	return 0;
}
# Loki - Obfuscator for x64 Binaries

## Project is a work-in-progress

## Features:

### Anti-Disassembly:

*   **ebff_decoys:** When an instruction starts with the byte `0xff`, an `0xeb` byte is prepended. This causes the CPU decoder to interpret it as a relative jump back to the original instruction, leading to incorrect static disassembly.
#pragma once


void fuku_asm_x86_jmp(obfurikuristruction& line, uint32_t offset) { //jmp offset
    uint8_t opcode[5];
    opcode[0] = 0xE9;
    *(uint32_t*)&opcode[1] = offset;
   
    line = obfurikuristruction().set_op_code(opcode, 5).set_type(I_JMP);
}
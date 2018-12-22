#include "stdafx.h"
#include "fuku_asm.h"

fuku_register registers64[] = { FUKU_REG_RAX, FUKU_REG_RCX, FUKU_REG_RDX,  FUKU_REG_RBX,  FUKU_REG_RSP,  FUKU_REG_RBP,  FUKU_REG_RSI,  FUKU_REG_RDI,
                                FUKU_REG_R8,  FUKU_REG_R9,  FUKU_REG_R10,  FUKU_REG_R11,  FUKU_REG_R12,  FUKU_REG_R13,  FUKU_REG_R14,  FUKU_REG_R15 };
fuku_register registers32[] = { FUKU_REG_EAX, FUKU_REG_ECX, FUKU_REG_EDX,  FUKU_REG_EBX,  FUKU_REG_ESP,  FUKU_REG_EBP,  FUKU_REG_ESI,  FUKU_REG_EDI, 
                                FUKU_REG_R8D, FUKU_REG_R9D, FUKU_REG_R10D, FUKU_REG_R11D, FUKU_REG_R12D, FUKU_REG_R13D, FUKU_REG_R14D, FUKU_REG_R15D };
fuku_register registers16[] = { FUKU_REG_AX,  FUKU_REG_CX,  FUKU_REG_DX,   FUKU_REG_BX,   FUKU_REG_SP,   FUKU_REG_BP,   FUKU_REG_SI,   FUKU_REG_DI,
                                FUKU_REG_R8W, FUKU_REG_R9W, FUKU_REG_R10W, FUKU_REG_R11W, FUKU_REG_R12W, FUKU_REG_R13W, FUKU_REG_R14W, FUKU_REG_R15W };
fuku_register registers8[] = {  FUKU_REG_AH,  FUKU_REG_CH,  FUKU_REG_DH,   FUKU_REG_BH,
                                FUKU_REG_AL,  FUKU_REG_CL,  FUKU_REG_DL,   FUKU_REG_BL,   FUKU_REG_SPL,  FUKU_REG_BPL,  FUKU_REG_SIL,  FUKU_REG_DIL,
                                FUKU_REG_R8B, FUKU_REG_R9B, FUKU_REG_R10B, FUKU_REG_R11B, FUKU_REG_R12B, FUKU_REG_R13B, FUKU_REG_R14B, FUKU_REG_R15B };


uint8_t fuku_get_index_reg(fuku_register reg) {

    switch (reg) {
        case FUKU_REG_R8:  case FUKU_REG_R8D: case FUKU_REG_R8W: case FUKU_REG_R8B:
        case FUKU_REG_RAX: case FUKU_REG_EAX: case FUKU_REG_AX:  case FUKU_REG_AH: 
        case FUKU_REG_AL: { return 0; }

        case FUKU_REG_R9:  case FUKU_REG_R9D: case FUKU_REG_R9W: case FUKU_REG_R9B:
        case FUKU_REG_RCX: case FUKU_REG_ECX: case FUKU_REG_CX:  case FUKU_REG_CH: 
        case FUKU_REG_CL: { return 1; }

        case FUKU_REG_R10: case FUKU_REG_R10D: case FUKU_REG_R10W: case FUKU_REG_R10B:
        case FUKU_REG_RDX: case FUKU_REG_EDX:  case FUKU_REG_DX:   case FUKU_REG_DH:
        case FUKU_REG_DL: { return 2; }

        case FUKU_REG_R11: case FUKU_REG_R11D: case FUKU_REG_R11W: case FUKU_REG_R11B:
        case FUKU_REG_RBX: case FUKU_REG_EBX:  case FUKU_REG_BX:   case FUKU_REG_BH:
        case FUKU_REG_BL: { return 3; }

        case FUKU_REG_R12: case FUKU_REG_R12D: case FUKU_REG_R12W: case FUKU_REG_R12B:
        case FUKU_REG_RSP: case FUKU_REG_ESP:  case FUKU_REG_SP:   case FUKU_REG_SPL: 
        { return 4; }

        case FUKU_REG_R13: case FUKU_REG_R13D: case FUKU_REG_R13W: case FUKU_REG_R13B:
        case FUKU_REG_RBP: case FUKU_REG_EBP:  case FUKU_REG_BP:   case FUKU_REG_BPL: 
        { return 5; }

        case FUKU_REG_R14: case FUKU_REG_R14D: case FUKU_REG_R14W: case FUKU_REG_R14B:
        case FUKU_REG_RSI: case FUKU_REG_ESI:  case FUKU_REG_SI:   case FUKU_REG_SIL: 
        { return 6; }

        case FUKU_REG_R15: case FUKU_REG_R15D: case FUKU_REG_R15W: case FUKU_REG_R15B:
        case FUKU_REG_RDI: case FUKU_REG_EDI:  case FUKU_REG_DI:   case FUKU_REG_DIL: 
        { return 7; }

    default: {
        return -1;
    }
    }
}

fuku_register fuku_get_reg_by_index(uint8_t idx, bool x64ext, fuku_operand_size size) {

    if (idx >= 8) {
        return fuku_register::FUKU_REG_NONE;
    }

    switch (size) {

        case FUKU_OPERAND_SIZE_8:
            return registers8[4 + idx + (x64ext == true ? 8 : 0)];

        case FUKU_OPERAND_SIZE_16:
            return registers16[idx + (x64ext == true ? 8 : 0)];

        case FUKU_OPERAND_SIZE_32:
            return registers32[idx + (x64ext == true ? 8 : 0)];

        case FUKU_OPERAND_SIZE_64:
            return registers64[idx + (x64ext == true ? 8 : 0)];


    default:
        return fuku_register::FUKU_REG_NONE;
    }
}

bool is_fuku_x64arch_reg(fuku_register reg) {

    if (reg == fuku_register::FUKU_REG_NONE || reg >= fuku_register::FUKU_REG_MAX) {
        return false;
    }

    switch (reg) {

        case FUKU_REG_RAX:
        case FUKU_REG_RCX:
        case FUKU_REG_RDX:
        case FUKU_REG_RBX:
        case FUKU_REG_RSP: case FUKU_REG_SPL:
        case FUKU_REG_RBP: case FUKU_REG_BPL:
        case FUKU_REG_RSI: case FUKU_REG_SIL:
        case FUKU_REG_RDI: case FUKU_REG_DIL:
        case FUKU_REG_R8:  case FUKU_REG_R8D:  case FUKU_REG_R8W:  case FUKU_REG_R8B:
        case FUKU_REG_R9:  case FUKU_REG_R9D:  case FUKU_REG_R9W:  case FUKU_REG_R9B:
        case FUKU_REG_R10: case FUKU_REG_R10D: case FUKU_REG_R10W: case FUKU_REG_R10B:
        case FUKU_REG_R11: case FUKU_REG_R11D: case FUKU_REG_R11W: case FUKU_REG_R11B:
        case FUKU_REG_R12: case FUKU_REG_R12D: case FUKU_REG_R12W: case FUKU_REG_R12B:
        case FUKU_REG_R13: case FUKU_REG_R13D: case FUKU_REG_R13W: case FUKU_REG_R13B:
        case FUKU_REG_R14: case FUKU_REG_R14D: case FUKU_REG_R14W: case FUKU_REG_R14B:
        case FUKU_REG_R15: case FUKU_REG_R15D: case FUKU_REG_R15W: case FUKU_REG_R15B: {
            return true;
        }

    default: {
        return false;
    }        
    }

    return false;
}

bool is_fuku_x32arch_reg(fuku_register reg) {

    if (reg == fuku_register::FUKU_REG_NONE || reg >= fuku_register::FUKU_REG_MAX) {
        return false;
    }

    return !is_fuku_x64arch_reg(reg);
}

bool is_fuku_64bit_reg(fuku_register reg) {

    if (reg == fuku_register::FUKU_REG_NONE || reg >= fuku_register::FUKU_REG_MAX) {
        return false;
    }

    switch (reg) {

        case FUKU_REG_RAX: case FUKU_REG_RCX: case FUKU_REG_RDX:
        case FUKU_REG_RBX: case FUKU_REG_RSP: case FUKU_REG_RBP:
        case FUKU_REG_RSI: case FUKU_REG_RDI:
        case FUKU_REG_R8:  case FUKU_REG_R9: case FUKU_REG_R10:
        case FUKU_REG_R11: case FUKU_REG_R12: case FUKU_REG_R13:
        case FUKU_REG_R14: case FUKU_REG_R15:{
            return true;
        }

    default: {
        return false;
    }
    }

    return false;
}

bool is_fuku_32bit_reg(fuku_register reg) {
    if (reg == fuku_register::FUKU_REG_NONE || reg >= fuku_register::FUKU_REG_MAX) {
        return false;
    }

    switch (reg) {

        case FUKU_REG_EAX:  case FUKU_REG_ECX: case FUKU_REG_EDX:
        case FUKU_REG_EBX:  case FUKU_REG_ESP: case FUKU_REG_EBP:
        case FUKU_REG_ESI:  case FUKU_REG_EDI:
        case FUKU_REG_R8B:  case FUKU_REG_R9B: case FUKU_REG_R10B:
        case FUKU_REG_R11B: case FUKU_REG_R12B: case FUKU_REG_R13B:
        case FUKU_REG_R14B: case FUKU_REG_R15B: {
            return true;
        }

    default: {
        return false;
    }
    }

    return false;
}

bool is_fuku_16bit_reg(fuku_register reg) {
    if (reg == fuku_register::FUKU_REG_NONE || reg >= fuku_register::FUKU_REG_MAX) {
        return false;
    }

    switch (reg) {

    case FUKU_REG_AX:  case FUKU_REG_CX: case FUKU_REG_DX:
    case FUKU_REG_BX:  case FUKU_REG_SP: case FUKU_REG_BP:
    case FUKU_REG_SI:  case FUKU_REG_DI:
    case FUKU_REG_R8W:  case FUKU_REG_R9W: case FUKU_REG_R10W:
    case FUKU_REG_R11W: case FUKU_REG_R12W: case FUKU_REG_R13W:
    case FUKU_REG_R14W: case FUKU_REG_R15W: {
        return true;
    }

    default: {
        return false;
    }
    }

    return false;
}

bool is_fuku_8bit_reg(fuku_register reg) {
    if (reg == fuku_register::FUKU_REG_NONE || reg >= fuku_register::FUKU_REG_MAX) {
        return false;
    }

    switch (reg) {

        case FUKU_REG_AL:   case FUKU_REG_CL:   case FUKU_REG_DL:   case FUKU_REG_BL:
        case FUKU_REG_AH:   case FUKU_REG_CH:   case FUKU_REG_DH:   case FUKU_REG_BH:
        case FUKU_REG_SPL:  case FUKU_REG_BPL:  case FUKU_REG_SIL:  case FUKU_REG_DIL:
        case FUKU_REG_R8B:  case FUKU_REG_R9B:  case FUKU_REG_R10B: case FUKU_REG_R11B: 
        case FUKU_REG_R12B: case FUKU_REG_R13B: case FUKU_REG_R14B: case FUKU_REG_R15B: {
            return true;
        }

    default: {
        return false;
    }
    }

    return false;
}


fuku_operand_size get_register_size(fuku_register reg) {
    if (reg == fuku_register::FUKU_REG_NONE || reg >= fuku_register::FUKU_REG_MAX) {
        return fuku_operand_size::FUKU_OPERAND_SIZE_0;
    }

    if (is_fuku_64bit_reg(reg)) {
        return fuku_operand_size::FUKU_OPERAND_SIZE_64;
    }
    else if (is_fuku_32bit_reg(reg)) {
        return fuku_operand_size::FUKU_OPERAND_SIZE_32;
    }
    else if (is_fuku_16bit_reg(reg)) {
        return fuku_operand_size::FUKU_OPERAND_SIZE_16;
    }
    else if (is_fuku_8bit_reg(reg)) {
        return fuku_operand_size::FUKU_OPERAND_SIZE_8;
    }

    return fuku_operand_size::FUKU_OPERAND_SIZE_0;
}


uint8_t fuku_to_capstone_reg(fuku_register reg) {
    return 0;
}

uint8_t capstone_to_fuku_reg(fuku_register reg) {
    return 0;
}


fuku_immediate::fuku_immediate()
    :immediate_value(0) {}

fuku_immediate::fuku_immediate(uint64_t immediate)
    : immediate_value(immediate) {}

fuku_immediate::~fuku_immediate() {};

fuku_immediate& fuku_immediate::set_relocate(bool is_rel) {
    this->relocate = is_rel;
    return *this;
}

fuku_immediate& fuku_immediate::set_immediate(uint64_t immediate) {
    this->immediate_value = immediate;
    return *this;
}

bool fuku_immediate::is_8() const {
    return (immediate_value & 0xFFFFFF00) == 0;
}
bool fuku_immediate::is_16() const {
    return (immediate_value & 0xFFFF0000) == 0;
}
bool fuku_immediate::is_32() const {
    return (immediate_value & 0xFFFF0000) != 0;
}
bool fuku_immediate::is_64() const {
    return (immediate_value & 0xFFFFFFFF00000000) != 0;
}
  
bool fuku_immediate::is_relocate() const {
    return this->relocate;
}

uint8_t fuku_immediate::get_immediate8() const {
    return this->immediate_value & 0xFF;
}

uint16_t fuku_immediate::get_immediate16() const {
    return this->immediate_value & 0xFFFF;
}

uint32_t fuku_immediate::get_immediate32() const {
    return this->immediate_value & 0xFFFFFFFF;
}

uint64_t fuku_immediate::get_immediate64() const {
    return this->immediate_value;
}

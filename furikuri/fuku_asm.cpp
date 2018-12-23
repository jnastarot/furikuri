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
x86_insn capstone_jcc[] = {
    X86_INS_JO , X86_INS_JNO ,
    X86_INS_JB , X86_INS_JAE ,
    X86_INS_JE, X86_INS_JNE,
    X86_INS_JBE , X86_INS_JA ,
    X86_INS_JS , X86_INS_JNS ,
    X86_INS_JP , X86_INS_JNP ,
    X86_INS_JL , X86_INS_JGE ,
    X86_INS_JLE , X86_INS_JG ,
};

fuku_register_index fuku_get_index_reg(fuku_register reg) {

    switch (reg) {
        case FUKU_REG_R8:  case FUKU_REG_R8D: case FUKU_REG_R8W: case FUKU_REG_R8B:
        case FUKU_REG_RAX: case FUKU_REG_EAX: case FUKU_REG_AX:  case FUKU_REG_AH: 
        case FUKU_REG_AL: { return fuku_register_index::FUKU_REG_INDEX_AX; }

        case FUKU_REG_R9:  case FUKU_REG_R9D: case FUKU_REG_R9W: case FUKU_REG_R9B:
        case FUKU_REG_RCX: case FUKU_REG_ECX: case FUKU_REG_CX:  case FUKU_REG_CH: 
        case FUKU_REG_CL: { return fuku_register_index::FUKU_REG_INDEX_CX; }

        case FUKU_REG_R10: case FUKU_REG_R10D: case FUKU_REG_R10W: case FUKU_REG_R10B:
        case FUKU_REG_RDX: case FUKU_REG_EDX:  case FUKU_REG_DX:   case FUKU_REG_DH:
        case FUKU_REG_DL: { return fuku_register_index::FUKU_REG_INDEX_DX; }

        case FUKU_REG_R11: case FUKU_REG_R11D: case FUKU_REG_R11W: case FUKU_REG_R11B:
        case FUKU_REG_RBX: case FUKU_REG_EBX:  case FUKU_REG_BX:   case FUKU_REG_BH:
        case FUKU_REG_BL: { return fuku_register_index::FUKU_REG_INDEX_BX; }

        case FUKU_REG_R12: case FUKU_REG_R12D: case FUKU_REG_R12W: case FUKU_REG_R12B:
        case FUKU_REG_RSP: case FUKU_REG_ESP:  case FUKU_REG_SP:   case FUKU_REG_SPL: 
        { return fuku_register_index::FUKU_REG_INDEX_SP; }

        case FUKU_REG_R13: case FUKU_REG_R13D: case FUKU_REG_R13W: case FUKU_REG_R13B:
        case FUKU_REG_RBP: case FUKU_REG_EBP:  case FUKU_REG_BP:   case FUKU_REG_BPL: 
        { return fuku_register_index::FUKU_REG_INDEX_BP; }

        case FUKU_REG_R14: case FUKU_REG_R14D: case FUKU_REG_R14W: case FUKU_REG_R14B:
        case FUKU_REG_RSI: case FUKU_REG_ESI:  case FUKU_REG_SI:   case FUKU_REG_SIL: 
        { return fuku_register_index::FUKU_REG_INDEX_SI; }

        case FUKU_REG_R15: case FUKU_REG_R15D: case FUKU_REG_R15W: case FUKU_REG_R15B:
        case FUKU_REG_RDI: case FUKU_REG_EDI:  case FUKU_REG_DI:   case FUKU_REG_DIL: 
        { return fuku_register_index::FUKU_REG_INDEX_DI; }

    default: {
        return fuku_register_index::FUKU_REG_INDEX_INVALID;
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
    return (
        immediate_value <= 0x7F ||
        immediate_value >= 0xFFFFFFFFFFFFFF80
        );
}
bool fuku_immediate::is_16() const {
    return (
        immediate_value <= 0x7FFF ||
        immediate_value >= 0xFFFFFFFFFFFF8000
        );
}
bool fuku_immediate::is_32() const {
    return (
        immediate_value <= 0x7FFFFFFF ||
        immediate_value >= 0xFFFFFFFF80000000
        );
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

int8_t fuku_immediate::get_signed_value8() const {
    return (int8_t)this->immediate_value;
}

int16_t fuku_immediate::get_signed_value16() const {
    return (int16_t)this->immediate_value;
}

int32_t fuku_immediate::get_signed_value32() const {
    return (int32_t)this->immediate_value;
}

int64_t fuku_immediate::get_signed_value64() const {
    return (int64_t)this->immediate_value;
}

x86_insn fuku_to_capstone_jcc(fuku_condition cond) {

    if (cond >=  FUKU_CONDITION_MAX || cond < 0) {
        return X86_INS_INVALID;
    }

    return capstone_jcc[cond];
}

fuku_condition capstone_to_fuku_jcc(x86_insn cond) {

    switch (cond) {
        case X86_INS_JO:    return fuku_condition::jo;
        case  X86_INS_JNO:  return fuku_condition::jno;
        case  X86_INS_JB:   return fuku_condition::jb;
        case  X86_INS_JAE:  return fuku_condition::jae;
        case  X86_INS_JE:   return fuku_condition::je;
        case  X86_INS_JNE:  return fuku_condition::jne;
        case  X86_INS_JBE:  return fuku_condition::jbe;
        case  X86_INS_JA:   return fuku_condition::ja;
        case  X86_INS_JS:   return fuku_condition::js;
        case  X86_INS_JNS:  return fuku_condition::jns;
        case  X86_INS_JP:   return fuku_condition::jp;
        case  X86_INS_JNP:  return fuku_condition::jnp;
        case  X86_INS_JL:   return fuku_condition::jl;
        case  X86_INS_JGE:  return fuku_condition::jge;
        case  X86_INS_JLE:  return fuku_condition::jle;
        case  X86_INS_JG:   return fuku_condition::jg;

        default: {
            return fuku_condition::jmp;
        }
    }
}
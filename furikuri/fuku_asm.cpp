#include "stdafx.h"
#include "fuku_asm.h"

struct {
	fuku_register register_;
	fuku_register_index register_index_;
	fuku_operand_size register_size_;
	bool is_x64_arch;
    bool is_x64_arch_ext;

} ext_register_info[] = {
	{FUKU_REG_NONE, (fuku_register_index)-1, fuku_operand_size::FUKU_OPERAND_SIZE_0, 0},

	{FUKU_REG_RAX, fuku_register_index::FUKU_REG_INDEX_AX, fuku_operand_size::FUKU_OPERAND_SIZE_64, true , false},
	{FUKU_REG_EAX, fuku_register_index::FUKU_REG_INDEX_AX, fuku_operand_size::FUKU_OPERAND_SIZE_32, false, false},
	{FUKU_REG_AX,  fuku_register_index::FUKU_REG_INDEX_AX, fuku_operand_size::FUKU_OPERAND_SIZE_16, false, false},
	{FUKU_REG_AH,  fuku_register_index::FUKU_REG_INDEX_AX, fuku_operand_size::FUKU_OPERAND_SIZE_8,	false, false},
	{FUKU_REG_AL,  fuku_register_index::FUKU_REG_INDEX_AX, fuku_operand_size::FUKU_OPERAND_SIZE_8,	false, false},

	{FUKU_REG_RCX, fuku_register_index::FUKU_REG_INDEX_CX, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, false},
	{FUKU_REG_ECX, fuku_register_index::FUKU_REG_INDEX_CX, fuku_operand_size::FUKU_OPERAND_SIZE_32, false, false},
	{FUKU_REG_CX,  fuku_register_index::FUKU_REG_INDEX_CX, fuku_operand_size::FUKU_OPERAND_SIZE_16, false, false},
	{FUKU_REG_CH,  fuku_register_index::FUKU_REG_INDEX_CX, fuku_operand_size::FUKU_OPERAND_SIZE_8,	false, false},
	{FUKU_REG_CL,  fuku_register_index::FUKU_REG_INDEX_CX, fuku_operand_size::FUKU_OPERAND_SIZE_8,	false, false},

	{FUKU_REG_RDX, fuku_register_index::FUKU_REG_INDEX_DX, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, false},
	{FUKU_REG_EDX, fuku_register_index::FUKU_REG_INDEX_DX, fuku_operand_size::FUKU_OPERAND_SIZE_32, false, false},
	{FUKU_REG_DX,  fuku_register_index::FUKU_REG_INDEX_DX, fuku_operand_size::FUKU_OPERAND_SIZE_16, false, false},
	{FUKU_REG_DH,  fuku_register_index::FUKU_REG_INDEX_DX, fuku_operand_size::FUKU_OPERAND_SIZE_8,	false, false},
	{FUKU_REG_DL,  fuku_register_index::FUKU_REG_INDEX_DX, fuku_operand_size::FUKU_OPERAND_SIZE_8,	false, false},

	{FUKU_REG_RBX, fuku_register_index::FUKU_REG_INDEX_BX, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, false},
	{FUKU_REG_EBX, fuku_register_index::FUKU_REG_INDEX_BX, fuku_operand_size::FUKU_OPERAND_SIZE_32, false, false},
	{FUKU_REG_BX,  fuku_register_index::FUKU_REG_INDEX_BX, fuku_operand_size::FUKU_OPERAND_SIZE_16, false, false},
	{FUKU_REG_BH,  fuku_register_index::FUKU_REG_INDEX_BX, fuku_operand_size::FUKU_OPERAND_SIZE_8,	false, false},
	{FUKU_REG_BL,  fuku_register_index::FUKU_REG_INDEX_BX, fuku_operand_size::FUKU_OPERAND_SIZE_8,	false, false},

	{FUKU_REG_RSP, fuku_register_index::FUKU_REG_INDEX_SP, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, false},
	{FUKU_REG_ESP, fuku_register_index::FUKU_REG_INDEX_SP, fuku_operand_size::FUKU_OPERAND_SIZE_32, false, false},
	{FUKU_REG_SP,  fuku_register_index::FUKU_REG_INDEX_SP, fuku_operand_size::FUKU_OPERAND_SIZE_16, false, false},
	{FUKU_REG_SPL, fuku_register_index::FUKU_REG_INDEX_SP, fuku_operand_size::FUKU_OPERAND_SIZE_8,	true, false},
    
    {FUKU_REG_RBP, fuku_register_index::FUKU_REG_INDEX_BP, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, false},
    {FUKU_REG_EBP, fuku_register_index::FUKU_REG_INDEX_BP, fuku_operand_size::FUKU_OPERAND_SIZE_32, false, false},
	{FUKU_REG_BP,  fuku_register_index::FUKU_REG_INDEX_BP, fuku_operand_size::FUKU_OPERAND_SIZE_16, false, false},
	{FUKU_REG_BPL, fuku_register_index::FUKU_REG_INDEX_BP, fuku_operand_size::FUKU_OPERAND_SIZE_8,	true, false},

	{FUKU_REG_RSI, fuku_register_index::FUKU_REG_INDEX_SI, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, false},
	{FUKU_REG_ESI, fuku_register_index::FUKU_REG_INDEX_SI, fuku_operand_size::FUKU_OPERAND_SIZE_32, false, false},
	{FUKU_REG_SI,  fuku_register_index::FUKU_REG_INDEX_SI, fuku_operand_size::FUKU_OPERAND_SIZE_16, false, false},
	{FUKU_REG_SIL, fuku_register_index::FUKU_REG_INDEX_SI, fuku_operand_size::FUKU_OPERAND_SIZE_8,	true, false},

	{FUKU_REG_RDI, fuku_register_index::FUKU_REG_INDEX_DI, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, false},
	{FUKU_REG_EDI, fuku_register_index::FUKU_REG_INDEX_DI, fuku_operand_size::FUKU_OPERAND_SIZE_32, false, false},
	{FUKU_REG_DI,  fuku_register_index::FUKU_REG_INDEX_DI, fuku_operand_size::FUKU_OPERAND_SIZE_16, false, false},
	{FUKU_REG_DIL, fuku_register_index::FUKU_REG_INDEX_DI, fuku_operand_size::FUKU_OPERAND_SIZE_8,	true, false},

    {FUKU_REG_R8,  fuku_register_index::FUKU_REG_INDEX_R8, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, true},
    {FUKU_REG_R8D, fuku_register_index::FUKU_REG_INDEX_R8, fuku_operand_size::FUKU_OPERAND_SIZE_32, true, true},
    {FUKU_REG_R8W, fuku_register_index::FUKU_REG_INDEX_R8, fuku_operand_size::FUKU_OPERAND_SIZE_16, true, true},
    {FUKU_REG_R8B, fuku_register_index::FUKU_REG_INDEX_R8, fuku_operand_size::FUKU_OPERAND_SIZE_8,	true, true},

    {FUKU_REG_R9,  fuku_register_index::FUKU_REG_INDEX_R9, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, true},
    {FUKU_REG_R9D, fuku_register_index::FUKU_REG_INDEX_R9, fuku_operand_size::FUKU_OPERAND_SIZE_32, true, true},
    {FUKU_REG_R9W, fuku_register_index::FUKU_REG_INDEX_R9, fuku_operand_size::FUKU_OPERAND_SIZE_16, true, true},
    {FUKU_REG_R9B, fuku_register_index::FUKU_REG_INDEX_R9, fuku_operand_size::FUKU_OPERAND_SIZE_8,	true, true},

    {FUKU_REG_R10,  fuku_register_index::FUKU_REG_INDEX_R10, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, true},
    {FUKU_REG_R10D, fuku_register_index::FUKU_REG_INDEX_R10, fuku_operand_size::FUKU_OPERAND_SIZE_32, true, true},
    {FUKU_REG_R10W, fuku_register_index::FUKU_REG_INDEX_R10, fuku_operand_size::FUKU_OPERAND_SIZE_16, true, true},
    {FUKU_REG_R10B, fuku_register_index::FUKU_REG_INDEX_R10, fuku_operand_size::FUKU_OPERAND_SIZE_8,  true, true},

    {FUKU_REG_R11,  fuku_register_index::FUKU_REG_INDEX_R11, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, true},
    {FUKU_REG_R11D, fuku_register_index::FUKU_REG_INDEX_R11, fuku_operand_size::FUKU_OPERAND_SIZE_32, true, true},
    {FUKU_REG_R11W, fuku_register_index::FUKU_REG_INDEX_R11, fuku_operand_size::FUKU_OPERAND_SIZE_16, true, true},
    {FUKU_REG_R11B, fuku_register_index::FUKU_REG_INDEX_R11, fuku_operand_size::FUKU_OPERAND_SIZE_8,  true, true},

    {FUKU_REG_R12,  fuku_register_index::FUKU_REG_INDEX_R12, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, true},
    {FUKU_REG_R12D, fuku_register_index::FUKU_REG_INDEX_R12, fuku_operand_size::FUKU_OPERAND_SIZE_32, true, true},
    {FUKU_REG_R12W, fuku_register_index::FUKU_REG_INDEX_R12, fuku_operand_size::FUKU_OPERAND_SIZE_16, true, true},
    {FUKU_REG_R12B, fuku_register_index::FUKU_REG_INDEX_R12, fuku_operand_size::FUKU_OPERAND_SIZE_8,  true, true},

    {FUKU_REG_R13,  fuku_register_index::FUKU_REG_INDEX_R13, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, true},
    {FUKU_REG_R13D, fuku_register_index::FUKU_REG_INDEX_R13, fuku_operand_size::FUKU_OPERAND_SIZE_32, true, true},
    {FUKU_REG_R13W, fuku_register_index::FUKU_REG_INDEX_R13, fuku_operand_size::FUKU_OPERAND_SIZE_16, true, true},
    {FUKU_REG_R13B, fuku_register_index::FUKU_REG_INDEX_R13, fuku_operand_size::FUKU_OPERAND_SIZE_8,  true, true},

    {FUKU_REG_R14,  fuku_register_index::FUKU_REG_INDEX_R14, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, true},
    {FUKU_REG_R14D, fuku_register_index::FUKU_REG_INDEX_R14, fuku_operand_size::FUKU_OPERAND_SIZE_32, true, true},
    {FUKU_REG_R14W, fuku_register_index::FUKU_REG_INDEX_R14, fuku_operand_size::FUKU_OPERAND_SIZE_16, true, true},
    {FUKU_REG_R14B, fuku_register_index::FUKU_REG_INDEX_R14, fuku_operand_size::FUKU_OPERAND_SIZE_8,  true, true},

    {FUKU_REG_R15,  fuku_register_index::FUKU_REG_INDEX_R15, fuku_operand_size::FUKU_OPERAND_SIZE_64, true, true},
    {FUKU_REG_R15D, fuku_register_index::FUKU_REG_INDEX_R15, fuku_operand_size::FUKU_OPERAND_SIZE_32, true, true},
    {FUKU_REG_R15W, fuku_register_index::FUKU_REG_INDEX_R15, fuku_operand_size::FUKU_OPERAND_SIZE_16, true, true},
    {FUKU_REG_R15B, fuku_register_index::FUKU_REG_INDEX_R15, fuku_operand_size::FUKU_OPERAND_SIZE_8,  true, true},
};


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

fuku_register_index fuku_get_index_by_register(fuku_register reg) {

    if (reg <= FUKU_REG_NONE || reg >= FUKU_REG_MAX) {
        return FUKU_REG_INDEX_INVALID;
    }

    return ext_register_info[reg].register_index_;
}

fuku_register fuku_get_register_by_index(fuku_register_index idx, bool x64ext, fuku_operand_size size) {

    if ( (idx < FUKU_REG_INDEX_AX || idx > FUKU_REG_INDEX_DI) ||
          (size <= FUKU_OPERAND_SIZE_0 || size > FUKU_OPERAND_SIZE_64)) {
        return FUKU_REG_NONE;
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
        return FUKU_REG_NONE;
    }
}

fuku_operand_size fuku_get_register_size(fuku_register reg) {
    if (reg <= FUKU_REG_NONE || reg >= FUKU_REG_MAX) {
        return FUKU_OPERAND_SIZE_0;
    }

    return ext_register_info[reg].register_size_;
}

bool fuku_is_x64arch_reg(fuku_register reg) {

    if (reg <= FUKU_REG_NONE || reg >= FUKU_REG_MAX) {
        return false;
    }

    return ext_register_info[reg].is_x64_arch;
}

bool fuku_is_x64arch_ext_reg(fuku_register reg) {

    if (reg <= FUKU_REG_NONE || reg >= FUKU_REG_MAX) {
        return false;
    }

    return ext_register_info[reg].is_x64_arch_ext;
}

bool fuku_is_x32arch_reg(fuku_register reg) {
    return !fuku_is_x64arch_reg(reg);
}

bool fuku_is_64bit_reg(fuku_register reg) {

    if (reg <= FUKU_REG_NONE || reg >= FUKU_REG_MAX) {
        return false;
    }

    return ext_register_info[reg].register_size_ == FUKU_OPERAND_SIZE_64;
}

bool fuku_is_32bit_reg(fuku_register reg) {
    if (reg <= FUKU_REG_NONE || reg >= FUKU_REG_MAX) {
        return false;
    }

    return ext_register_info[reg].register_size_ == FUKU_OPERAND_SIZE_32;
}

bool fuku_is_16bit_reg(fuku_register reg) {
    if (reg <= FUKU_REG_NONE || reg >= FUKU_REG_MAX) {
        return false;
    }

    return ext_register_info[reg].register_size_ == FUKU_OPERAND_SIZE_16;
}

bool fuku_is_8bit_reg(fuku_register reg) {
    if (reg <= FUKU_REG_NONE || reg >= FUKU_REG_MAX) {
        return false;
    }

    return ext_register_info[reg].register_size_ == FUKU_OPERAND_SIZE_8;
}

uint8_t fuku_to_capstone_reg(fuku_register reg) {
    return 0;
}

uint8_t capstone_to_fuku_reg(fuku_register reg) {
    return 0;
}


fuku_immediate::fuku_immediate()
    :immediate_value(0), relocate(false){}

fuku_immediate::fuku_immediate(uint64_t immediate)
    : immediate_value(immediate), relocate(false) {}

fuku_immediate::fuku_immediate(uint64_t immediate, bool is_rel)
    : immediate_value(immediate), relocate(is_rel) {}


fuku_immediate::~fuku_immediate() {};

fuku_immediate& fuku_immediate::operator=(const fuku_immediate& imm) {
    this->relocate = imm.relocate;
    this->immediate_value = imm.immediate_value;
    return *this;
}

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



fuku_operand::fuku_operand(const fuku_immediate& disp)
    : base(FUKU_REG_NONE), index(FUKU_REG_NONE), scale(FUKU_OPERAND_SCALE_1), disp(disp){}

fuku_operand::fuku_operand(fuku_register base, const fuku_immediate& disp) 
    : base(base), index(FUKU_REG_NONE), scale(FUKU_OPERAND_SCALE_1), disp(disp) {}

fuku_operand::fuku_operand(fuku_register base, fuku_register index, fuku_operand_scale scale, const fuku_immediate& disp)
    : base(base), index(index), scale(scale), disp(disp) {}

fuku_operand::fuku_operand(fuku_register index, fuku_operand_scale scale, const fuku_immediate& disp) 
    : base(FUKU_REG_NONE), index(index), scale(scale), disp(disp) {}

fuku_operand::~fuku_operand() {}

void fuku_operand::set_base(fuku_register base) {
    this->base = base;
}

void fuku_operand::set_index(fuku_register index) {
    this->index = index;
}

void fuku_operand::set_scale(fuku_operand_scale scale) {
    this->scale = scale;
}

void fuku_operand::set_disp(const fuku_immediate& disp) {
    this->disp = disp;
}

fuku_register fuku_operand::get_base() const {
    return this->base;
}

fuku_register fuku_operand::get_index() const {
    return this->index;
}

fuku_operand_scale fuku_operand::get_scale() const {
    return this->scale;
}

const fuku_immediate& fuku_operand::get_disp() const {
    return this->disp;
}

fuku_mem_opernad_type fuku_operand::get_type() const {
   
    if (base != FUKU_REG_NONE) {
        if (index != FUKU_REG_NONE) {
            if (disp.get_immediate64()) {
                return fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_INDEX_DISP;
            }
            else {
                return fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_INDEX;
            }
        }
        else {
            if (disp.get_immediate64()) {
                return fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_DISP;
            }
            else {
                return fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_ONLY;
            }
        }
    }
    else {
        if (index != FUKU_REG_NONE) {
            return fuku_mem_opernad_type::FUKU_MEM_OPERAND_INDEX_DISP;
        }
        else {
            return fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_DISP;
        }
    }
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
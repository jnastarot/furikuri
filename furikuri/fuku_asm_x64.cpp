#include "stdafx.h"
#include "fuku_asm_x64.h"
#include "fuku_asm_x64_macro.h"


#define set_modrm(mod, reg_idx) \
    FUKU_ASSERT_EQ(mod & -4, 0)\
    raw_operand[0] = (uint8_t(mod) << 6) | reg_idx;\
    operand_size = 1;


#define set_sib(scale,reg_index,reg_idx_index,reg_idx_base)\
    FUKU_ASSERT_EQ(operand_size, 1);\
    FUKU_ASSERT_EQ(scale & -4, 0);\
    FUKU_ASSERT((!fuku_is_x64arch_ext_reg(reg_index) && reg_idx_index == FUKU_REG_INDEX_SP) || reg_idx_base == FUKU_REG_INDEX_SP);\
    raw_operand[1] = (scale << 6) | (reg_idx_index << 3) | reg_idx_base;\
    operand_size = 2;

#define set_disp8(disp)\
    raw_operand[operand_size] = (uint8_t)disp;\
    displacment_offset = length + operand_size;\
    operand_size += sizeof(int8_t);

#define set_dispr(disp)\
    *(uint32_t*)&raw_operand[operand_size] = disp;\
    displacment_offset = length + operand_size;\
    operand_size += sizeof(uint32_t);


fuku_asm_x64::fuku_asm_x64()
    : short_cfg(FUKU_ASM_SHORT_CFG_USE_EAX_SHORT | FUKU_ASM_SHORT_CFG_USE_DISP_SHORT | FUKU_ASM_SHORT_CFG_USE_IMM_SHORT) {}

fuku_asm_x64::~fuku_asm_x64(){}

uint8_t fuku_asm_x64::get_displacment_offset() {
    return this->displacment_offset;
}

uint8_t fuku_asm_x64::get_immediate_offset() {
    return this->immediate_offset;
}

bool fuku_asm_x64::is_used_short_eax() {
    return this->short_cfg & FUKU_ASM_SHORT_CFG_USE_EAX_SHORT;
}

bool fuku_asm_x64::is_used_short_disp() {
    return this->short_cfg & FUKU_ASM_SHORT_CFG_USE_DISP_SHORT;
}

bool fuku_asm_x64::is_used_short_imm() {
    return this->short_cfg & FUKU_ASM_SHORT_CFG_USE_IMM_SHORT;
}


void fuku_asm_x64::clear_space() {
    memset(bytecode, 0, sizeof(bytecode));
    this->length = 0;
    this->displacment_offset = 0;
    this->immediate_offset = 0;
}

void fuku_asm_x64::emit_b(uint8_t x) {
    bytecode[length] = x;
    length++;
}

void fuku_asm_x64::emit_w(uint16_t x) {
    *(uint16_t*)&bytecode[length] = x;
    length += sizeof(uint16_t);
}

void fuku_asm_x64::emit_dw(uint32_t x) {
    *(uint32_t*)&bytecode[length] = x;
    length += sizeof(uint32_t);
}

void fuku_asm_x64::emit_qw(uint64_t x) {
    *(uint64_t*)&bytecode[length] = x;
    length += sizeof(uint64_t);
}

void fuku_asm_x64::emit_immediate_b(fuku_immediate& src) {
    bytecode[length] = src.get_immediate8();
    length++;
}

void fuku_asm_x64::emit_immediate_w(fuku_immediate& src) {
    *(uint16_t*)&bytecode[length] = src.get_immediate16();
    length += sizeof(uint16_t);
}

void fuku_asm_x64::emit_immediate_dw(fuku_immediate& src) {
    *(uint32_t*)&bytecode[length] = src.get_immediate32();
    length += sizeof(uint32_t);
}

void fuku_asm_x64::emit_immediate_qw(fuku_immediate& src) {
    *(uint64_t*)&bytecode[length] = src.get_immediate64();
    length += sizeof(uint64_t);
}


/*
                          is base 64 ext(B)
         is reg 64 ext(R)  /
                 |        /
    REX 0100 0   0   0   0
             |        \
      is 64bit size(W) \
                      is index 64 ext(X)
*/

void fuku_asm_x64::emit_rex(bool x64bit_size, bool x64ext_reg, bool x64ext_index, bool x64ext_base) {
    if ( (x64bit_size || x64ext_reg || x64ext_index || x64ext_base) ) {
        emit_b(0x40 | (x64bit_size ? 8 : 0) | (x64ext_reg ? 4 : 0) | (x64ext_index ? 2 : 0) | (x64ext_base ? 1 : 0));
    }
}

void fuku_asm_x64::emit_rex_64() { 
    emit_b(0x48);
}

void fuku_asm_x64::emit_rex_64(fuku_register reg, fuku_register rm_reg) {
    emit_b(0x48 | fuku_is_x64arch_ext_reg(reg) << 2 | fuku_is_x64arch_ext_reg(rm_reg));
}

void fuku_asm_x64::emit_rex_64(fuku_register reg, const fuku_operand& op) {
    emit_b(0x48 | fuku_is_x64arch_ext_reg(reg) << 2 | op.get_low_rex());
}

void fuku_asm_x64::emit_rex_64(fuku_register rm_reg) {
    emit_b(0x48 | fuku_is_x64arch_ext_reg(rm_reg));
}

void fuku_asm_x64::emit_rex_64(const fuku_operand& op) { 
    emit_b(0x48 | op.get_low_rex());
}

void fuku_asm_x64::emit_rex_32(fuku_register reg, fuku_register rm_reg) {
    emit_b(0x40 | fuku_is_x64arch_ext_reg(reg) << 2 | fuku_is_x64arch_ext_reg(rm_reg));
}

void fuku_asm_x64::emit_rex_32(fuku_register reg, const fuku_operand& op) {
    emit_b(0x40 | fuku_is_x64arch_ext_reg(reg) << 2 | op.get_low_rex());
}


void fuku_asm_x64::emit_rex_32(fuku_register rm_reg) {
    emit_b(0x40 | fuku_is_x64arch_ext_reg(rm_reg));
}

void fuku_asm_x64::emit_rex_32(const fuku_operand& op) { emit_b(0x40 | op.get_low_rex()); }

void fuku_asm_x64::emit_optional_rex_32(fuku_register reg, fuku_register rm_reg) {
    uint8_t rex_bits = fuku_is_x64arch_ext_reg(reg) << 2 | fuku_is_x64arch_ext_reg(rm_reg);
    if (rex_bits != 0) { emit_b(0x40 | rex_bits); }
}

void fuku_asm_x64::emit_optional_rex_32(fuku_register reg, const fuku_operand& op) {
    uint8_t rex_bits = fuku_is_x64arch_ext_reg(reg) << 2 | op.get_low_rex();
    if (rex_bits != 0) { emit_b(0x40 | rex_bits); }
}


void fuku_asm_x64::emit_optional_rex_32(fuku_register rm_reg) {
    if (fuku_is_x64arch_ext_reg(rm_reg)) { emit_b(0x41); }
}

void fuku_asm_x64::emit_optional_rex_32(const fuku_operand& op) {
    if (op.get_low_rex() != 0) { emit_b(0x40 | op.get_low_rex()); }
}

void fuku_asm_x64::emit_rex(fuku_operand_size size) {
    if (size == fuku_operand_size::FUKU_OPERAND_SIZE_64) {
        emit_rex_64();
    }
}

void fuku_asm_x64::emit_rex(const fuku_operand& reg, fuku_operand_size size) {
    if (size == fuku_operand_size::FUKU_OPERAND_SIZE_64) {
        emit_rex_64(reg);
    }
    else {
        emit_optional_rex_32(reg);
    }
}
void fuku_asm_x64::emit_rex(fuku_register reg, fuku_operand_size size) {
    if (size == fuku_operand_size::FUKU_OPERAND_SIZE_64) {
        emit_rex_64(reg);
    }
    else {
        emit_optional_rex_32(reg);
    }
}

void fuku_asm_x64::emit_rex(fuku_register reg, fuku_register rm_reg, fuku_operand_size size) {
    if (size == fuku_operand_size::FUKU_OPERAND_SIZE_64) {
        emit_rex_64(reg, rm_reg);
    }
    else {
        emit_optional_rex_32(reg, rm_reg);
    }
}

void fuku_asm_x64::emit_rex(fuku_register reg, const fuku_operand& rm_reg, fuku_operand_size size) {
    if (size == fuku_operand_size::FUKU_OPERAND_SIZE_64) {
        emit_rex_64(reg, rm_reg);
    }
    else {
        emit_optional_rex_32(reg, rm_reg);
    }
}

void fuku_asm_x64::emit_modrm(fuku_register reg, fuku_register rm_reg) {
    emit_b(0xC0 | fuku_get_index_by_register(reg) << 3 | fuku_get_index_by_register(rm_reg));
}

void fuku_asm_x64::emit_modrm(int code, fuku_register rm_reg) {
    emit_b(0xC0 | code << 3 | fuku_get_index_by_register(rm_reg));
}


void fuku_asm_x64::emit_operand(fuku_register_index reg, const fuku_operand& rm_reg) {

    uint8_t raw_operand[6] = { 0 };
    uint8_t operand_size = 0;

    uint8_t base_idx = fuku_get_index_by_register(rm_reg.get_base());
    uint8_t index_idx = fuku_get_index_by_register(rm_reg.get_index());

    switch (rm_reg.get_type()) {

    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_DISP_ONLY: {
        set_modrm(0, FUKU_REG_INDEX_BP);
        set_dispr(rm_reg.get_disp().get_immediate32());
        break;
    }

    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_ONLY:
    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_DISP: {

        // [base + disp/r]
        if (rm_reg.get_disp().get_immediate32() == 0 && base_idx != FUKU_REG_INDEX_BP) {

            // [base]
            set_modrm(0, base_idx);
        }
        else if (is_used_short_disp() && rm_reg.get_disp().is_8()) {

            // [base + disp8]
            set_modrm(1, base_idx);
            set_disp8(rm_reg.get_disp().get_immediate8());
        }
        else {

            // [base + disp/r]
            set_modrm(2, base_idx);
            set_dispr(rm_reg.get_disp().get_immediate32());
        }

        break;
    }

    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_INDEX:
    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_INDEX_DISP: {

        FUKU_ASSERT(index_idx != FUKU_REG_INDEX_SP);

        set_sib(rm_reg.get_scale(), rm_reg.get_index(), index_idx, base_idx);

        // [base + index*scale + disp/r]
        if (rm_reg.get_disp().get_immediate32() == 0 && base_idx != FUKU_REG_INDEX_BP) {
            // [base + index*scale]
            set_modrm(0, FUKU_REG_INDEX_SP);    
        }
        else if (is_used_short_disp() && rm_reg.get_disp().is_8()) {
            // [base + index*scale + disp8]
            set_modrm(1, FUKU_REG_INDEX_SP);
            set_disp8(rm_reg.get_disp().get_immediate8());
        }
        else {
            // [base + index*scale + disp/r]
            set_modrm(2, FUKU_REG_INDEX_SP);
            set_dispr(rm_reg.get_disp().get_immediate32());
        }

        break;
    }
    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_INDEX_DISP: {
        FUKU_ASSERT(index_idx != FUKU_REG_INDEX_SP);

        // [index*scale + disp/r]
        set_modrm(0, FUKU_REG_INDEX_SP);
        set_sib(rm_reg.get_scale(), rm_reg.get_index(), index_idx, FUKU_REG_INDEX_BP);
        set_dispr(rm_reg.get_disp().get_immediate32());
        break;
    }


    default:FUKU_DEBUG;
    }

    bytecode[length] = raw_operand[0] | reg << 3;

    for (unsigned i = 1; i < operand_size; i++) { bytecode[length + i] = raw_operand[i]; }
    length += operand_size;
}



fuku_instruction fuku_asm_x64::nop(int n) {

    clear_space();
    while (n > 0) {
        switch (n) {
        case 2:
            emit_b(0x66);
        case 1:
            emit_b(0x90);
            return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NOP).set_eflags(0);
        case 3:
            emit_b(0x0F);
            emit_b(0x1F);
            emit_b(0x00);
            return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NOP).set_eflags(0);
        case 4:
            emit_b(0x0F);
            emit_b(0x1F);
            emit_b(0x40);
            emit_b(0x00);
            return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NOP).set_eflags(0);
        case 6:
            emit_b(0x66);
        case 5:
            emit_b(0x0F);
            emit_b(0x1F);
            emit_b(0x44);
            emit_b(0x00);
            emit_b(0x00);
            return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NOP).set_eflags(0);
        case 7:
            emit_b(0x0F);
            emit_b(0x1F);
            emit_b(0x80);
            emit_b(0x00);
            emit_b(0x00);
            emit_b(0x00);
            emit_b(0x00);
            return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NOP).set_eflags(0);
        default:
        case 11:
            emit_b(0x66);
            n--;
        case 10:
            emit_b(0x66);
            n--;
        case 9:
            emit_b(0x66);
            n--;
        case 8:
            emit_b(0x0F);
            emit_b(0x1F);
            emit_b(0x84);
            emit_b(0x00);
            emit_b(0x00);
            emit_b(0x00);
            emit_b(0x00);
            emit_b(0x00);
            n -= 8;
        }
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NOP).set_eflags(0);
}

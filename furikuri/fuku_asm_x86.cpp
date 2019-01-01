#include "stdafx.h"
#include "fuku_asm_x86.h"
#include "fuku_asm_86_macro.h"



#define set_modrm(mod, reg_idx) \
    FUKU_ASSERT_EQ(mod & -4, 0)\
    raw_operand[0] = (uint8_t(mod) << 6) | reg_idx;\
    operand_size = 1;


#define set_sib(scale,reg_idx_index,reg_idx_base)\
    FUKU_ASSERT_EQ(operand_size, 1);\
    FUKU_ASSERT_EQ(scale & -4, 0);\
    FUKU_ASSERT(reg_idx_index != FUKU_REG_INDEX_SP || reg_idx_base == FUKU_REG_INDEX_SP);\
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


fuku_asm_x86::fuku_asm_x86()
    : short_cfg(FUKU_ASM_SHORT_CFG_USE_EAX_SHORT | FUKU_ASM_SHORT_CFG_USE_DISP_SHORT | FUKU_ASM_SHORT_CFG_USE_IMM_SHORT){
    clear_space();
}
fuku_asm_x86::~fuku_asm_x86(){}

uint8_t fuku_asm_x86::get_displacment_offset() {
    return this->displacment_offset;
}

uint8_t fuku_asm_x86::get_immediate_offset() {
    return this->immediate_offset;
}

bool fuku_asm_x86::is_used_short_eax() {
    return this->short_cfg & FUKU_ASM_SHORT_CFG_USE_EAX_SHORT;
}

bool fuku_asm_x86::is_used_short_disp() {
    return this->short_cfg & FUKU_ASM_SHORT_CFG_USE_DISP_SHORT;
}

bool fuku_asm_x86::is_used_short_imm() {
    return this->short_cfg & FUKU_ASM_SHORT_CFG_USE_IMM_SHORT;
}

void fuku_asm_x86::clear_space() {
    memset(bytecode, 0, sizeof(bytecode));
    this->length = 0;
    this->immediate_offset = 0;
    this->displacment_offset = 0;
}


void fuku_asm_x86::emit_b(uint8_t x) {
    bytecode[length] = x;
    length++;
}
void fuku_asm_x86::emit_w(uint16_t x) {
    *(uint16_t*)&bytecode[length] = x;
    length += sizeof(uint16_t);
}
void fuku_asm_x86::emit_dw(uint32_t x) {
    *(uint32_t*)&bytecode[length] = x;
    length += sizeof(uint32_t);
}
void fuku_asm_x86::emit_immediate_b(const fuku_immediate& imm) {
    bytecode[length] = imm.get_immediate8();
    immediate_offset = length;
    length++;
}
void fuku_asm_x86::emit_immediate_w(const fuku_immediate& imm) {
    *(uint16_t*)&bytecode[length] = imm.get_immediate16();
    immediate_offset = length;
    length += sizeof(uint16_t);
}
void fuku_asm_x86::emit_immediate_dw(const fuku_immediate& imm) {
    *(uint32_t*)&bytecode[length] = imm.get_immediate32();
    immediate_offset = length;
    length += sizeof(uint32_t);
}

void fuku_asm_x86::emit_operand(fuku_register_index reg,const fuku_operand& adr) {    
    FUKU_ASSERT_GT(length, 0);

    uint8_t raw_operand[6] = { 0 };
    uint8_t operand_size = 0;
    
    uint8_t base_idx = fuku_get_index_reg(adr.get_base());
    uint8_t index_idx = fuku_get_index_reg(adr.get_index());

    switch (adr.get_type()) {

    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_DISP_ONLY: {
        set_modrm(0, FUKU_REG_INDEX_BP);
        set_dispr(adr.get_disp().get_immediate32());
        break;
    }

    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_ONLY: 
    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_DISP: {

        // [base + disp/r]
        if (adr.get_disp().get_immediate32() == 0 && base_idx != FUKU_REG_INDEX_BP) {

            // [base]
            set_modrm(0, base_idx);
            if (base_idx == FUKU_REG_INDEX_SP) {
                set_sib(FUKU_OPERAND_SCALE_1, FUKU_REG_INDEX_SP, base_idx);
            }
        }
        else if (is_used_short_disp() && adr.get_disp().is_8()) {

            // [base + disp8]
            set_modrm(1, base_idx);
            if (fuku_get_index_reg(adr.get_base()) == FUKU_REG_INDEX_SP) {
                set_sib(FUKU_OPERAND_SCALE_1, FUKU_REG_INDEX_SP, base_idx);
            }
            set_disp8(adr.get_disp().get_immediate8());
        }
        else {

            // [base + disp/r]
            set_modrm(2, base_idx);
            if (base_idx == FUKU_REG_INDEX_SP) {
                set_sib(FUKU_OPERAND_SCALE_1, FUKU_REG_INDEX_SP, base_idx);
            }
            set_dispr(adr.get_disp().get_immediate32());
        }

        break;
    }

    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_INDEX:
    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_BASE_INDEX_DISP: {

        FUKU_ASSERT(index_idx != FUKU_REG_INDEX_SP);

        // [base + index*scale + disp/r]
        if (adr.get_disp().get_immediate32() == 0 && base_idx != FUKU_REG_INDEX_BP) {
            // [base + index*scale]
            set_modrm(0, FUKU_REG_INDEX_SP);
            set_sib(adr.get_scale(), index_idx, base_idx);
        }
        else if (is_used_short_disp() && adr.get_disp().is_8()) {
            // [base + index*scale + disp8]
            set_modrm(1, FUKU_REG_INDEX_SP);
            set_sib(adr.get_scale(), index_idx, base_idx);
            set_disp8(adr.get_disp().get_immediate8());
        }
        else {
            // [base + index*scale + disp/r]
            set_modrm(2, FUKU_REG_INDEX_SP);
            set_sib(adr.get_scale(), index_idx, base_idx);
            set_dispr(adr.get_disp().get_immediate32());
        }

        break;
    }
    case fuku_mem_opernad_type::FUKU_MEM_OPERAND_INDEX_DISP: {
        FUKU_ASSERT(index_idx != FUKU_REG_INDEX_SP);

        // [index*scale + disp/r]
        set_modrm(0, FUKU_REG_INDEX_SP);
        set_sib(adr.get_scale(), index_idx, FUKU_REG_INDEX_BP);
        set_dispr(adr.get_disp().get_immediate32());
        break;
    }


    default:FUKU_DEBUG;
    }


    bytecode[length] = (raw_operand[0] & ~0x38) | (reg << 3);

    for (unsigned i = 1; i < operand_size; i++) {
        bytecode[length + i] = raw_operand[i];
    }

    length += operand_size;
}


gen_func_body_twobyte_no_arg(_pusha,  FUKU_PREFIX_OVERRIDE_DATA, 0x60, X86_INS_PUSHAW, 0)
gen_func_body_onebyte_no_arg(_pushad, 0x60, X86_INS_PUSHAL, 0)
gen_func_body_twobyte_no_arg(_popa,   FUKU_PREFIX_OVERRIDE_DATA, 0x61, X86_INS_POPAW, 0)
gen_func_body_onebyte_no_arg(_popad,  0x61, X86_INS_POPAL, 0)

gen_func_body_twobyte_no_arg(_pushf,  FUKU_PREFIX_OVERRIDE_DATA, 0x9C, X86_INS_PUSHF, 0)
gen_func_body_onebyte_no_arg(_pushfd, 0x9C, X86_INS_PUSHFD, 0)
gen_func_body_twobyte_no_arg(_popf,   FUKU_PREFIX_OVERRIDE_DATA, 0x9D, X86_INS_POPF, X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_TF | X86_EFLAGS_MODIFY_IF | X86_EFLAGS_MODIFY_DF | X86_EFLAGS_MODIFY_NT)
gen_func_body_onebyte_no_arg(_popfd,  0x9D, X86_INS_POPFD, X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_TF | X86_EFLAGS_MODIFY_IF | X86_EFLAGS_MODIFY_DF | X86_EFLAGS_MODIFY_NT | X86_EFLAGS_MODIFY_RF)

gen_func_body_ff_offset(_call, 0xF8, X86_INS_CALL, 0)
gen_func_body_ff_r(     _call, 2   , X86_INS_CALL, 0)
gen_func_body_ff_op(    _call, 2   , X86_INS_CALL, 0)
gen_func_body_ff_offset(_jmp,  0xF9, X86_INS_JMP,  0)
gen_func_body_ff_r(     _jmp,  4   , X86_INS_JMP,  0)
gen_func_body_ff_op(    _jmp,  4   , X86_INS_JMP,  0)

gen_func_body_onebyte_no_arg(_ret, 0xC3, X86_INS_RET, 0)

gen_func_body_arith(add, asm86_arith_add, X86_INS_ADD, X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF    | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)
gen_func_body_arith(or,  asm86_arith_or,  X86_INS_OR,  X86_EFLAGS_RESET_OF  | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
gen_func_body_arith(adc, asm86_arith_adc, X86_INS_ADC, X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF    | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)
gen_func_body_arith(sbb, asm86_arith_sbb, X86_INS_SBB, X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF    | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)
gen_func_body_arith(and, asm86_arith_and, X86_INS_AND, X86_EFLAGS_RESET_OF  | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
gen_func_body_arith(sub, asm86_arith_sub, X86_INS_SUB, X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF    | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)
gen_func_body_arith(xor, asm86_arith_xor, X86_INS_XOR, X86_EFLAGS_RESET_OF  | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
gen_func_body_arith(cmp, asm86_arith_cmp, X86_INS_CMP, X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF    | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)

gen_func_body_arith_ex_one_op(not,  asm86_arith_ex_not,  X86_INS_NOT,  0)
gen_func_body_arith_ex_one_op(neg,  asm86_arith_ex_neg,  X86_INS_NEG,  X86_EFLAGS_MODIFY_OF    | X86_EFLAGS_MODIFY_SF    | X86_EFLAGS_MODIFY_ZF    | X86_EFLAGS_MODIFY_AF    | X86_EFLAGS_MODIFY_PF    | X86_EFLAGS_MODIFY_CF)
gen_func_body_arith_ex_one_op(mul,  asm86_arith_ex_mul,  X86_INS_MUL,  X86_EFLAGS_MODIFY_SF    | X86_EFLAGS_MODIFY_CF    | X86_EFLAGS_MODIFY_OF    | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF)
gen_func_body_arith_ex_one_op(imul, asm86_arith_ex_imul, X86_INS_IMUL, X86_EFLAGS_MODIFY_SF    | X86_EFLAGS_MODIFY_CF    | X86_EFLAGS_MODIFY_OF    | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF)
gen_func_body_arith_ex_one_op(div,  asm86_arith_ex_div,  X86_INS_DIV,  X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_CF)
gen_func_body_arith_ex_one_op(idiv, asm86_arith_ex_idiv, X86_INS_IDIV, X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_CF)

gen_func_body_arith_incdec(inc, asm86_arith_inc, X86_INS_INC, X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF)
gen_func_body_arith_incdec(dec, asm86_arith_dec, X86_INS_DEC, X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF)


gen_func_body_shift(rol, asm86_shift_rol, X86_INS_ROL, X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF)
gen_func_body_shift(ror, asm86_shift_rol, X86_INS_ROR, X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF)
gen_func_body_shift(rcl, asm86_shift_rol, X86_INS_RCL, X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF)
gen_func_body_shift(rcr, asm86_shift_rol, X86_INS_RCR, X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF)
gen_func_body_shift(shl, asm86_shift_rol, X86_INS_SHL, X86_EFLAGS_MODIFY_OF    | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)
gen_func_body_shift(shr, asm86_shift_rol, X86_INS_SHR, X86_EFLAGS_MODIFY_OF    | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)
gen_func_body_shift(sar, asm86_shift_rol, X86_INS_SAR, X86_EFLAGS_MODIFY_OF    | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF)

gen_func_body_bittest(bt , asm86_bittest_bt,  X86_INS_BT,  X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF)
gen_func_body_bittest(bts, asm86_bittest_bts, X86_INS_BTS, X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF)
gen_func_body_bittest(btr, asm86_bittest_btr, X86_INS_BTR, X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF)
gen_func_body_bittest(btc, asm86_bittest_btc, X86_INS_BTC, X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF)


gen_func_body_onebyte_no_arg(_movsb, 0xA4,                            X86_INS_MOVSB, 0)
gen_func_body_twobyte_no_arg(_movsw, FUKU_PREFIX_OVERRIDE_DATA, 0xA5, X86_INS_MOVSW, 0)
gen_func_body_onebyte_no_arg(_movsd, 0xA5,                            X86_INS_MOVSD, 0)
gen_func_body_onebyte_no_arg(_stosb, 0xAA,                            X86_INS_STOSB, 0)
gen_func_body_twobyte_no_arg(_stosw, FUKU_PREFIX_OVERRIDE_DATA, 0xAB, X86_INS_STOSW, 0)
gen_func_body_onebyte_no_arg(_stosd, 0xAB,                            X86_INS_STOSD, 0)

gen_func_body_onebyte_no_arg(_nop,    0x90, X86_INS_NOP,   0)
gen_func_body_onebyte_no_arg(_cdq,    0x99, X86_INS_CDQ,   0)
gen_func_body_onebyte_no_arg(_stosb,  0xAB, X86_INS_STOSB, 0)
gen_func_body_onebyte_no_arg(leave_,  0xC9, X86_INS_LEAVE, 0)
gen_func_body_onebyte_no_arg(_int3,   0xCC, X86_INS_INT3,  0)
gen_func_body_onebyte_no_arg(_hlt,    0xF4, X86_INS_HLT,   0)
gen_func_body_onebyte_no_arg(_cld,    0xFC, X86_INS_CLD,   X86_EFLAGS_RESET_DF)

gen_func_body_twobyte_no_arg(_ud2,   0x0F, 0x0B, X86_INS_UD2,   0)
gen_func_body_twobyte_no_arg(_rdtsc, 0x0F, 0x31, X86_INS_RDTSC, 0)
gen_func_body_twobyte_no_arg(_cpuid, 0x0F, 0xA2, X86_INS_CPUID, 0)
gen_func_body_twobyte_no_arg(_pause, 0xF3, 0x90, X86_INS_PAUSE, 0)

gen_func_body_threebyte_no_arg(_lfence, 0x0F, 0xAE, 0xE8, X86_INS_LFENCE, 0)

genrettype_asm86 fuku_asm_x86::_jcc(fuku_condition cond, const fuku_immediate& imm) {
    gencleanerdata
    
    FUKU_ASSERT(cond < 0 || cond >= fuku_condition::FUKU_CONDITION_MAX);

    emit_b(0x0F);
    emit_b(0x80 | cond);
    emit_immediate_dw(imm);


    static uint64_t di_fl_jcc[] = {
        X86_EFLAGS_TEST_OF , X86_EFLAGS_TEST_OF,
        X86_EFLAGS_TEST_CF , X86_EFLAGS_TEST_CF,
        X86_EFLAGS_TEST_ZF , X86_EFLAGS_TEST_ZF,
        X86_EFLAGS_TEST_ZF | X86_EFLAGS_TEST_CF, X86_EFLAGS_TEST_ZF | X86_EFLAGS_TEST_CF,
        X86_EFLAGS_TEST_SF , X86_EFLAGS_TEST_SF,
        X86_EFLAGS_TEST_PF , X86_EFLAGS_TEST_PF,
        X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF, X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF,
        X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_ZF, X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_ZF
    };

    gen_func_return(fuku_to_capstone_jcc(cond), di_fl_jcc[cond])
}


genrettype_asm86 fuku_asm_x86::_ret(const fuku_immediate& imm) {
    gencleanerdata
    emit_b(0xC2);
    emit_immediate_w(imm);
    gen_func_return(X86_INS_RET, 0)
}


genrettype_asm86 fuku_asm_x86::_push_w(const fuku_immediate& imm) {
    gencleanerdata
     emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    if (imm.is_8()) {
        emit_b(0x6A);
        emit_immediate_b(imm);
    }
    else {
        emit_b(0x68);
        emit_immediate_w(imm);
    }
    gen_func_return(X86_INS_PUSH, 0)
}

genrettype_asm86 fuku_asm_x86::_push_dw(const fuku_immediate& imm) {
    gencleanerdata
    if (imm.is_8()) {
        emit_b(0x6A);
        emit_immediate_b(imm);
    }
    else {
        emit_b(0x68);
        emit_immediate_dw(imm);
    }
    gen_func_return(X86_INS_PUSH, 0)
}

genrettype_asm86 fuku_asm_x86::_push_w(fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x50 | fuku_get_index_reg(src));
    gen_func_return(X86_INS_PUSH, 0)
}

genrettype_asm86 fuku_asm_x86::_push_dw(fuku_register src) {
    gencleanerdata
    emit_b(0x50 | fuku_get_index_reg(src));
    gen_func_return(X86_INS_PUSH, 0)
}

genrettype_asm86 fuku_asm_x86::_push_w(const fuku_operand& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0xFF);
    emit_operand((fuku_register_index)4, src);
    gen_func_return(X86_INS_PUSH, 0)
}

genrettype_asm86 fuku_asm_x86::_push_dw(const fuku_operand& src) {
    gencleanerdata
    emit_b(0xFF);
    emit_operand((fuku_register_index)4, src);
    gen_func_return(X86_INS_PUSH, 0)
}

genrettype_asm86 fuku_asm_x86::_pop_w(fuku_register dst) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x58 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_POP, 0)
}

genrettype_asm86 fuku_asm_x86::_pop_dw(fuku_register dst) {
    gencleanerdata
    emit_b(0x58 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_POP, 0)
}

genrettype_asm86 fuku_asm_x86::_pop_w(const fuku_operand& dst) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x8F);
    emit_operand((fuku_register_index)0, dst);
    gen_func_return(X86_INS_POP, 0)
}

genrettype_asm86 fuku_asm_x86::_pop_dw(const fuku_operand& dst) {
    gencleanerdata
    emit_b(0x8F);
    emit_operand((fuku_register_index)0, dst);
    gen_func_return(X86_INS_POP, 0)
}



genrettype_asm86 fuku_asm_x86::_enter(const fuku_immediate& size, uint8_t nestinglevel) {
    gencleanerdata
    emit_b(0xC8);
    emit_immediate_w(size);
    emit_b(nestinglevel);
    gen_func_return(X86_INS_ENTER, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_b(fuku_register dst, fuku_register src) { 
    gencleanerdata
    emit_b(0x88);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst) );
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_b(fuku_register dst,const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xB0 | fuku_get_index_reg(dst));
    emit_immediate_b(src);
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_b(fuku_register dst, const fuku_operand& src) {
    gencleanerdata
    if(is_used_short_eax() && dst == fuku_register::FUKU_REG_AX &&
        src.get_type() == fuku_mem_opernad_type::FUKU_MEM_OPERAND_DISP_ONLY ){
        emit_b(0xA0); 
        emit_dw(src.get_disp().get_immediate32());
        displacment_offset = length;
    }
    else {
        emit_b(0x8A);
        emit_operand(fuku_get_index_reg(dst), src);
    }
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_b(const fuku_operand& dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xC6);
    emit_operand(FUKU_REG_INDEX_AX, dst);
    emit_immediate_b(src);
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_b(const fuku_operand& dst, fuku_register src) {
    gencleanerdata
    if(is_used_short_eax() && src == fuku_register::FUKU_REG_AX &&
        dst.get_type() == fuku_mem_opernad_type::FUKU_MEM_OPERAND_DISP_ONLY ){
        emit_b(0xA2); 
        emit_dw(dst.get_disp().get_immediate32());
        displacment_offset = length;
    }
    else {
        emit_b(0x88);
        emit_operand(fuku_get_index_reg(src), dst);
    }
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_w(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x89);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_w(fuku_register dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0xB8 | fuku_get_index_reg(dst));
    emit_immediate_w(src);
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_w(fuku_register dst, const fuku_operand& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    if (is_used_short_eax() && dst == fuku_register::FUKU_REG_AX &&
        src.get_type() == fuku_mem_opernad_type::FUKU_MEM_OPERAND_DISP_ONLY) {
        emit_b(0xA1);
        emit_dw(src.get_disp().get_immediate32());
        displacment_offset = length;
    }
    else {
        emit_b(0x8B);
        emit_operand(fuku_get_index_reg(dst), src);
    }
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_w(const fuku_operand& dst, fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    if (is_used_short_eax() && src == fuku_register::FUKU_REG_AX &&
        dst.get_type() == fuku_mem_opernad_type::FUKU_MEM_OPERAND_DISP_ONLY) {
        emit_b(0xA3);
        emit_dw(dst.get_disp().get_immediate32());
        displacment_offset = length;
    }
    else {
        emit_b(0x89);
        emit_operand(fuku_get_index_reg(src), dst);
    }
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_w(const fuku_operand& dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0xC7);
    emit_operand(FUKU_REG_INDEX_AX, dst);
    emit_immediate_w(src);  
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_dw(fuku_register dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xB8 | fuku_get_index_reg(dst));
    emit_immediate_dw(src);
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_dw(fuku_register dst, const fuku_operand& src) {
    gencleanerdata
    if (is_used_short_eax() && dst == fuku_register::FUKU_REG_AX &&
        src.get_type() == fuku_mem_opernad_type::FUKU_MEM_OPERAND_DISP_ONLY) {
        emit_b(0xA3);
        emit_dw(src.get_disp().get_immediate32());
        displacment_offset = length;
    }
    else {
        emit_b(0x8B);
        emit_operand(fuku_get_index_reg(dst), src);
    }
    gen_func_return(X86_INS_MOV, 0)
}


genrettype_asm86 fuku_asm_x86::_mov_dw(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x89);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_dw(const fuku_operand& dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xC7);
    emit_operand(FUKU_REG_INDEX_AX, dst);
    emit_immediate_dw(src);
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_mov_dw(const fuku_operand& dst, fuku_register src) {
    gencleanerdata
    if (is_used_short_eax() && src == fuku_register::FUKU_REG_AX &&
        dst.get_type() == fuku_mem_opernad_type::FUKU_MEM_OPERAND_DISP_ONLY) {
        emit_b(0xA3);
        emit_dw(dst.get_disp().get_immediate32());
        displacment_offset = length;
    }
    else {
        emit_b(0x89);
        emit_operand(fuku_get_index_reg(src), dst);
    }
    gen_func_return(X86_INS_MOV, 0)
}

genrettype_asm86 fuku_asm_x86::_movsx_b(fuku_register dst, const fuku_operand& src) {
    gencleanerdata

    
    if (is_fuku_16bit_reg(dst)) {
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    }

    emit_b(0x0F);
    emit_b(0xBE);
    emit_operand(fuku_get_index_reg(dst), src);

    gen_func_return(X86_INS_MOVSX, 0)
}

genrettype_asm86 fuku_asm_x86::_movsx_b(fuku_register dst, fuku_register src) {
    gencleanerdata

    if (is_fuku_16bit_reg(dst)) {
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    }

    emit_b(0x0F);
    emit_b(0xBE);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));

    gen_func_return(X86_INS_MOVSX, 0)
}

genrettype_asm86 fuku_asm_x86::_movsx_w(fuku_register dst, const fuku_operand& src) {
    gencleanerdata


    emit_b(0x0F);
    emit_b(0xBF);
    emit_operand(fuku_get_index_reg(dst), src);

    gen_func_return(X86_INS_MOVSX, 0)
}

genrettype_asm86 fuku_asm_x86::_movsx_w(fuku_register dst, fuku_register src) {
    gencleanerdata

    emit_b(0x0F);
    emit_b(0xBF);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));

    gen_func_return(X86_INS_MOVSX, 0)
}

genrettype_asm86 fuku_asm_x86::_movzx_b(fuku_register dst, const fuku_operand& src) {
    gencleanerdata

    if (is_fuku_16bit_reg(dst)) {
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    }

    emit_b(0x0F);
    emit_b(0xB6);
    emit_operand(fuku_get_index_reg(dst), src);

    gen_func_return(X86_INS_MOVZX, 0)
}

genrettype_asm86 fuku_asm_x86::_movzx_b(fuku_register dst, fuku_register src) {
    gencleanerdata

    if (is_fuku_16bit_reg(dst)) {
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    }

    emit_b(0x0F);
    emit_b(0xB6);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_MOVZX, 0)
}

genrettype_asm86 fuku_asm_x86::_movzx_w(fuku_register dst, const fuku_operand& src) {
    gencleanerdata
    emit_b(0x0F);
    emit_b(0xB7);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_MOVZX, 0)
}

genrettype_asm86 fuku_asm_x86::_movzx_w(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x0F);
    emit_b(0xB7);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_MOVZX, 0)
}

genrettype_asm86 fuku_asm_x86::_xchg_b(fuku_register dst, const fuku_operand& src) {
    gencleanerdata
    emit_b(0x86);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_XCHG, 0)
}

genrettype_asm86 fuku_asm_x86::_xchg_b(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x86);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_XCHG, 0)
}

genrettype_asm86 fuku_asm_x86::_xchg_w(fuku_register dst, const fuku_operand& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x87);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_XCHG, 0)
}


genrettype_asm86 fuku_asm_x86::_xchg_w(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x87);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_XCHG, 0)
}

genrettype_asm86 fuku_asm_x86::_xchg_dw(fuku_register dst, const fuku_operand& src) {
    gencleanerdata
    emit_b(0x87);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_XCHG, 0)
}


genrettype_asm86 fuku_asm_x86::_xchg_dw(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x87);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_XCHG, 0)
}


genrettype_asm86 fuku_asm_x86::_lea_w(fuku_register dst, const fuku_operand& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x8D);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_LEA, 0)
}

genrettype_asm86 fuku_asm_x86::_lea_dw(fuku_register dst, const fuku_operand& src) {
    gencleanerdata
    emit_b(0x8D);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_LEA, 0)
}


genrettype_asm86 fuku_asm_x86::_test_b(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x84);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}

genrettype_asm86 fuku_asm_x86::_test_b(fuku_register dst, const fuku_immediate& src) {
    gencleanerdata
    if (is_used_short_eax() && dst == fuku_register::FUKU_REG_AL) {
        emit_b(0xA8);
    }
    else {
        emit_b(0xF6);
        emit_b(0xC0 | fuku_get_index_reg(dst));
    }
    emit_immediate_b(src);
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}

genrettype_asm86 fuku_asm_x86::_test_b(const fuku_operand& dst, fuku_register src) {
    gencleanerdata
    emit_b(0x84);
    emit_operand(fuku_get_index_reg(src), dst);
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}
genrettype_asm86 fuku_asm_x86::_test_b(const fuku_operand& dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xF6);
    emit_operand((fuku_register_index)0, dst);
    emit_immediate_b(src);
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}

genrettype_asm86 fuku_asm_x86::_test_w(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);  
    emit_b(0x85);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}

genrettype_asm86 fuku_asm_x86::_test_w(fuku_register dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    if (is_used_short_eax() && dst == fuku_register::FUKU_REG_AX) {
        emit_b(0xA9);
    }
    else {
        emit_b(0xF7);
        emit_b(0xC0 | fuku_get_index_reg(dst));
    }
    emit_immediate_w(src);
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}

genrettype_asm86 fuku_asm_x86::_test_w(const fuku_operand& dst, fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x85);
    emit_operand(fuku_get_index_reg(src), dst);
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}
genrettype_asm86 fuku_asm_x86::_test_w(const fuku_operand& dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0xF7);
    emit_operand((fuku_register_index)0, dst);
    emit_immediate_w(src);
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}

genrettype_asm86 fuku_asm_x86::_test_dw(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x85);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}

genrettype_asm86 fuku_asm_x86::_test_dw(fuku_register dst, const fuku_immediate& src) {
    gencleanerdata
    if (is_used_short_eax() && dst == fuku_register::FUKU_REG_EAX) {
        emit_b(0xA9);
    }
    else {
        emit_b(0xF7);
        emit_b(0xC0 | fuku_get_index_reg(dst));
    }
    emit_immediate_dw(src);
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}

genrettype_asm86 fuku_asm_x86::_test_dw(const fuku_operand& dst, fuku_register src) {
    gencleanerdata
    emit_b(0x85);
    emit_operand(fuku_get_index_reg(src), dst);
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}
genrettype_asm86 fuku_asm_x86::_test_dw(const fuku_operand& dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xF7);
    emit_operand((fuku_register_index)0, dst);
    emit_immediate_dw(src);
    gen_func_return(X86_INS_TEST, X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF)
}


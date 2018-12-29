#include "stdafx.h"
#include "fuku_asm_x86.h"
#include "fuku_asm_86_macro.h"



void fuku_operand86::set_modrm(uint32_t mod, uint32_t reg_idx) {
    FUKU_ASSERT_EQ(mod & -4, 0)
    raw_operand[0] = (uint8_t(mod) << 6) | reg_idx;
    operand_size = 1;
}

void fuku_operand86::set_sib(fuku_operand_scale scale, uint32_t reg_idx_index, uint32_t reg_idx_base) {
    FUKU_ASSERT_EQ(operand_size, 1);
    FUKU_ASSERT_EQ(scale & -4, 0);
    // Use SIB with no index register only for base esp.
    FUKU_ASSERT(reg_idx_index != FUKU_REG_INDEX_SP || reg_idx_base == FUKU_REG_INDEX_SP);

    raw_operand[1] = (scale << 6) | (reg_idx_index << 3) | reg_idx_base;
    operand_size = 2;
}

void fuku_operand86::set_disp8(int8_t disp) {
    FUKU_ASSERT(operand_size == 1 || operand_size == 2);
    raw_operand[operand_size] = disp;
    disp_offset = operand_size;
    operand_size += sizeof(int8_t);
}
void fuku_operand86::set_dispr(int32_t disp) {
    FUKU_ASSERT(operand_size == 1 || operand_size == 2);
    *(int32_t*)&raw_operand[operand_size] = disp;
    disp_offset = operand_size;
    operand_size += sizeof(int32_t);
}

fuku_operand86::fuku_operand86(fuku_register reg) { 
    operand_size = 0; 
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

    set_modrm(3, fuku_get_index_reg(reg));
}

fuku_operand86::fuku_operand86(uint32_t disp) {
    operand_size = 0; 
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

    set_modrm(0, FUKU_REG_INDEX_BP);
    set_dispr(disp);
}

fuku_operand86::fuku_operand86(fuku_register base, uint32_t disp) {
    operand_size = 0;
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

    uint8_t base_idx = fuku_get_index_reg(base);

    // [base + disp/r]
    if (disp == 0 && base_idx != FUKU_REG_INDEX_BP) {
        
        // [base]
        set_modrm(0, base_idx);
        if (base_idx == FUKU_REG_INDEX_SP) {
            set_sib(FUKU_OPERAND_SCALE_1, FUKU_REG_INDEX_SP, base_idx);
        }
    }
    else if (!(disp & 0xFFFFFF00)) {

        // [base + disp8]
        set_modrm(1, base_idx);
        if (fuku_get_index_reg(base) == FUKU_REG_INDEX_SP) {
            set_sib(FUKU_OPERAND_SCALE_1, FUKU_REG_INDEX_SP, base_idx);
        }
        set_disp8(disp);
    }
    else {
        
        // [base + disp/r]
        set_modrm(2, base_idx);
        if (base_idx == FUKU_REG_INDEX_SP) {
            set_sib(FUKU_OPERAND_SCALE_1, FUKU_REG_INDEX_SP, base_idx);
        }
        set_dispr(disp);
    }
}

fuku_operand86::fuku_operand86(fuku_register base, fuku_register index, fuku_operand_scale scale, uint32_t disp) {
    operand_size = 0; 
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

    uint8_t index_idx = fuku_get_index_reg(index);
    uint8_t base_idx = fuku_get_index_reg(base);

    FUKU_ASSERT(index_idx != FUKU_REG_INDEX_SP);

    // [base + index*scale + disp/r]
    if (disp == 0 && base_idx != FUKU_REG_INDEX_BP) {
        // [base + index*scale]
        set_modrm(0, FUKU_REG_INDEX_SP);
        set_sib(scale, index_idx, base_idx);
    }
    else if (!(disp & 0xFFFFFF00)) {
        // [base + index*scale + disp8]
        set_modrm(1, FUKU_REG_INDEX_SP);
        set_sib(scale, index_idx, base_idx);
        set_disp8(disp);
    }
    else {
        // [base + index*scale + disp/r]
        set_modrm(2, FUKU_REG_INDEX_SP);
        set_sib(scale, index_idx, base_idx);
        set_dispr(disp);
    }
}

fuku_operand86::fuku_operand86(fuku_register index, fuku_operand_scale scale, uint32_t disp) {
    operand_size = 0; 
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

    FUKU_ASSERT(fuku_get_index_reg(index) != FUKU_REG_INDEX_SP);

    // [index*scale + disp/r]
    set_modrm(0, FUKU_REG_INDEX_SP);
    set_sib(scale, fuku_get_index_reg(index), FUKU_REG_INDEX_BP);
    set_dispr(disp);
}

fuku_register_index fuku_operand86::get_register() const {
    FUKU_ASSERT(is_register_only());
    return fuku_register_index(raw_operand[0] & 0x07);
}
bool fuku_operand86::is_register_only() const {
    return (raw_operand[0] & 0xF8) == 0xC0;
}
const uint8_t* fuku_operand86::get_raw_operand() const {
    return this->raw_operand;
}
uint8_t fuku_operand86::get_operand_size() const {
    return this->operand_size;
}

uint8_t fuku_operand86::get_disp_offset() const {
    return this->disp_offset;
}

fuku_operand86::~fuku_operand86() {}


fuku_asm_x86::fuku_asm_x86(){
    clear_space();
}
fuku_asm_x86::~fuku_asm_x86(){}

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

void fuku_asm_x86::emit_arith(int sel, const fuku_operand86& dst, const fuku_immediate& imm) {

    FUKU_ASSERT((0 <= sel) && (sel <= 7));

    if (imm.is_8()) {
        emit_b(0x83);
        emit_operand(fuku_register_index(sel), dst);
        emit_immediate_b(imm);
    }
    else if (dst.get_register() == FUKU_REG_INDEX_AX) {
        emit_b((sel << 3) | 0x05);
        emit_immediate_dw(imm);
    }
    else {
        emit_b(0x81);
        emit_operand(fuku_register_index(sel), dst);
        emit_immediate_dw(imm);
    }
}

void fuku_asm_x86::emit_operand(fuku_register_index reg,const fuku_operand86& adr) {

    FUKU_ASSERT_GT(length, 0);

    bytecode[length] = (adr.get_raw_operand()[0] & ~0x38) | (reg << 3);

    for (unsigned i = 1; i < adr.get_operand_size(); i++) {
        bytecode[length + i] = adr.get_raw_operand()[i];
    }
    
    if (adr.get_disp_offset()) {
        this->displacment_offset = length + adr.get_disp_offset();
    }

    length += adr.get_operand_size();
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


fuku_instruction fuku_asm_x86::_jcc(fuku_condition cond, uint32_t offset) {
    gencleanerdata
    
    FUKU_ASSERT(cond < 0 || cond >= fuku_condition::FUKU_CONDITION_MAX);

    emit_b(0x0F);
    emit_b(0x80 | cond);
    emit_dw(offset);


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

gen_func_body_onebyte_no_arg(_ret, 0xC3, X86_INS_RET, 0)

fuku_instruction fuku_asm_x86::_ret(uint16_t imm16) {
    gencleanerdata
    emit_b(0xC2);
    emit_w(imm16);
    gen_func_return(X86_INS_RET, 0)
}


fuku_instruction fuku_asm_x86::_push_w(const fuku_immediate& imm) {
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

fuku_instruction fuku_asm_x86::_push_dw(const fuku_immediate& imm) {
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

fuku_instruction fuku_asm_x86::_push_w(fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x50 | fuku_get_index_reg(src));
    gen_func_return(X86_INS_PUSH, 0)
}

fuku_instruction fuku_asm_x86::_push_dw(fuku_register src) {
    gencleanerdata
    emit_b(0x50 | fuku_get_index_reg(src));
    gen_func_return(X86_INS_PUSH, 0)
}

fuku_instruction fuku_asm_x86::_push_w(const fuku_operand86& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0xFF);
    emit_operand((fuku_register_index)4, src);
    gen_func_return(X86_INS_PUSH, 0)
}

fuku_instruction fuku_asm_x86::_push_dw(const fuku_operand86& src) {
    gencleanerdata
    emit_b(0xFF);
    emit_operand((fuku_register_index)4, src);
    gen_func_return(X86_INS_PUSH, 0)
}

fuku_instruction fuku_asm_x86::_pop_w(fuku_register dst) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x58 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_POP, 0)
}

fuku_instruction fuku_asm_x86::_pop_dw(fuku_register dst) {
    gencleanerdata
    emit_b(0x58 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_POP, 0)
}

fuku_instruction fuku_asm_x86::_pop_w(const fuku_operand86& dst) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x8F);
    emit_operand((fuku_register_index)0, dst);
    gen_func_return(X86_INS_POP, 0)
}

fuku_instruction fuku_asm_x86::_pop_dw(const fuku_operand86& dst) {
    gencleanerdata
    emit_b(0x8F);
    emit_operand((fuku_register_index)0, dst);
    gen_func_return(X86_INS_POP, 0)
}



fuku_instruction fuku_asm_x86::_enter(const fuku_immediate& size, uint8_t nestinglevel) {
    gencleanerdata
    emit_b(0xC8);
    emit_immediate_w(size);
    emit_b(nestinglevel);
    gen_func_return(X86_INS_ENTER, 0)
}

fuku_instruction fuku_asm_x86::_mov_b(fuku_register dst, fuku_register src) { 
    gencleanerdata
    emit_b(0x88);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst) );
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_b(fuku_register dst,const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xB0 | fuku_get_index_reg(dst));
    emit_immediate_b(src);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_b(fuku_register dst, const fuku_operand86& src) {
    gencleanerdata
    emit_b(0x8A);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_b(const fuku_operand86& dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xC6);
    emit_operand(FUKU_REG_INDEX_AX, dst);
    emit_immediate_b(src);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_b(const fuku_operand86& dst, fuku_register src) {
    gencleanerdata
    emit_b(0x88);
    emit_operand(fuku_get_index_reg(src), dst);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_w(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x89);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_w(fuku_register dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0xB8 | fuku_get_index_reg(dst));
    emit_immediate_w(src);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_w(fuku_register dst, const fuku_operand86& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x8B);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_w(const fuku_operand86& dst, fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x89);
    emit_operand(fuku_get_index_reg(src), dst);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_w(const fuku_operand86& dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0xC7);
    emit_operand(FUKU_REG_INDEX_AX, dst);
    emit_immediate_w(src);  
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_dw(fuku_register dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xB8 | fuku_get_index_reg(dst));
    emit_immediate_dw(src);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_dw(fuku_register dst, const fuku_operand86& src) {
    gencleanerdata
    emit_b(0x8B);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_MOV, 0)
}


fuku_instruction fuku_asm_x86::_mov_dw(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x89);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_dw(const fuku_operand86& dst, const fuku_immediate& src) {
    gencleanerdata
    emit_b(0xC7);
    emit_operand(FUKU_REG_INDEX_AX, dst);
    emit_immediate_dw(src);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_mov_dw(const fuku_operand86& dst, fuku_register src) {
    gencleanerdata
    emit_b(0x89);
    emit_operand(fuku_get_index_reg(src), dst);
    gen_func_return(X86_INS_MOV, 0)
}

fuku_instruction fuku_asm_x86::_movsx_b(fuku_register dst, fuku_operand86& src) {
    gencleanerdata

    
    if (is_fuku_16bit_reg(dst)) {
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    }

    emit_b(0x0F);
    emit_b(0xBE);
    emit_operand(fuku_get_index_reg(dst), src);

    gen_func_return(X86_INS_MOVSX, 0)
}

fuku_instruction fuku_asm_x86::_movsx_b(fuku_register dst, fuku_register src) {
    gencleanerdata

    if (is_fuku_16bit_reg(dst)) {
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    }

    emit_b(0x0F);
    emit_b(0xBE);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));

    gen_func_return(X86_INS_MOVSX, 0)
}

fuku_instruction fuku_asm_x86::_movsx_w(fuku_register dst, fuku_operand86& src) {
    gencleanerdata


    emit_b(0x0F);
    emit_b(0xBF);
    emit_operand(fuku_get_index_reg(dst), src);

    gen_func_return(X86_INS_MOVSX, 0)
}

fuku_instruction fuku_asm_x86::_movsx_w(fuku_register dst, fuku_register src) {
    gencleanerdata

    emit_b(0x0F);
    emit_b(0xBF);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));

    gen_func_return(X86_INS_MOVSX, 0)
}

fuku_instruction fuku_asm_x86::_movzx_b(fuku_register dst, fuku_operand86& src) {
    gencleanerdata

    if (is_fuku_16bit_reg(dst)) {
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    }

    emit_b(0x0F);
    emit_b(0xB6);
    emit_operand(fuku_get_index_reg(dst), src);

    gen_func_return(X86_INS_MOVZX, 0)
}

fuku_instruction fuku_asm_x86::_movzx_b(fuku_register dst, fuku_register src) {
    gencleanerdata

    if (is_fuku_16bit_reg(dst)) {
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    }

    emit_b(0x0F);
    emit_b(0xB6);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_MOVZX, 0)
}

fuku_instruction fuku_asm_x86::_movzx_w(fuku_register dst, fuku_operand86& src) {
    gencleanerdata
    emit_b(0x0F);
    emit_b(0xB7);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_MOVZX, 0)
}

fuku_instruction fuku_asm_x86::_movzx_w(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x0F);
    emit_b(0xB7);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_MOVZX, 0)
}

fuku_instruction fuku_asm_x86::_xchg_b(fuku_register dst, const fuku_operand86& src) {
    gencleanerdata
    emit_b(0x86);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_XCHG, 0)
}

fuku_instruction fuku_asm_x86::_xchg_b(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x86);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_XCHG, 0)
}

fuku_instruction fuku_asm_x86::_xchg_w(fuku_register dst, const fuku_operand86& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x87);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_XCHG, 0)
}


fuku_instruction fuku_asm_x86::_xchg_w(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x87);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_XCHG, 0)
}

fuku_instruction fuku_asm_x86::_xchg_dw(fuku_register dst, const fuku_operand86& src) {
    gencleanerdata
    emit_b(0x87);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_XCHG, 0)
}


fuku_instruction fuku_asm_x86::_xchg_dw(fuku_register dst, fuku_register src) {
    gencleanerdata
    emit_b(0x87);
    emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));
    gen_func_return(X86_INS_XCHG, 0)
}


fuku_instruction fuku_asm_x86::_lea_w(fuku_register dst, const fuku_operand86& src) {
    gencleanerdata
    emit_b(FUKU_PREFIX_OVERRIDE_DATA);
    emit_b(0x8D);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_LEA, 0)
}

fuku_instruction fuku_asm_x86::_lea_dw(fuku_register dst, const fuku_operand86& src) {
    gencleanerdata
    emit_b(0x8D);
    emit_operand(fuku_get_index_reg(dst), src);
    gen_func_return(X86_INS_LEA, 0)
}


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



/*

fuku_instruction fuku_asm_x86::cmpxchg(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xB1);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMPXCHG).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmpxchg_b(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xB0);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMPXCHG8B).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmpxchg_w(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x66);
    emit_b(0x0F);
    emit_b(0xB1);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMPXCHG16B).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}




fuku_instruction fuku_asm_x86::rcl(fuku_register dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_b(0xD0 | dst);
    }
    else {
        emit_b(0xC1);
        emit_b(0xD0 | dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_RCL).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF);
}


fuku_instruction fuku_asm_x86::rcr(fuku_register dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_b(0xD8 | dst);
    }
    else {
        emit_b(0xC1);
        emit_b(0xD8 | dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_RCR).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::ror(fuku_register dst, uint8_t imm8) { 
    return ror(fuku_operand86(dst), imm8);
}

fuku_instruction fuku_asm_x86::ror_cl(fuku_register dst) { 
    return ror_cl(fuku_operand86(dst)); 
}

fuku_instruction fuku_asm_x86::ror(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_register::r_ECX, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_register::r_ECX, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ROR).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::ror_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_register::r_ECX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ROR).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::rol(fuku_register dst, uint8_t imm8) {
    return rol(fuku_operand86(dst), imm8);
}

fuku_instruction fuku_asm_x86::rol_cl(fuku_register dst) {
    return rol_cl(fuku_operand86(dst));
}

fuku_instruction fuku_asm_x86::rol(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_register::r_EAX, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_register::r_EAX, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ROL).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::rol_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_register::r_EAX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ROL).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::sar(fuku_register dst, uint8_t imm8) { 
    return sar(fuku_operand86(dst), imm8);
}

fuku_instruction fuku_asm_x86::sar_cl(fuku_register dst) { 
    return sar_cl(fuku_operand86(dst));
}

fuku_instruction fuku_asm_x86::sar(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_register::r_EDI, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_register::r_EDI, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SAR).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::sar_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_register::r_EDI, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SAR).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}


fuku_instruction fuku_asm_x86::shld(fuku_register dst, fuku_register src, uint8_t shift) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xA4);
    emit_operand(src, fuku_operand86(dst));
    emit_b(shift);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SHLD).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::shld_cl(fuku_register dst, fuku_register src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xA5);
    emit_operand(src, fuku_operand86(dst));
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SHLD).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::shl(fuku_register dst, uint8_t imm8) { 
    return shl(fuku_operand86(dst), imm8); 
}

fuku_instruction fuku_asm_x86::shl(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_register::r_ESP, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_register::r_ESP, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SHL).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::shl_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_register::r_ESP, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SHL).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::shr(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_register::r_EBP, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_register::r_EBP, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SHR).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::shr_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_register::r_EBP, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SHR).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::shrd(fuku_register dst, fuku_register src, uint8_t shift) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAC);
    emit_operand(dst, fuku_operand86(src));
    emit_b(shift);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SHRD).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::shrd_cl(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAD);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SHRD).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}


fuku_instruction fuku_asm_x86::test(fuku_register reg0, fuku_register reg1) { 
    return test(reg0, fuku_operand86(reg1)); 
}

fuku_instruction fuku_asm_x86::test(fuku_register reg, fuku_immediate& imm) {
    if (imm.is_imm_8()) {        
        return test_b(reg, imm);
    }

    clear_space();
    if (reg == fuku_register::r_EAX) {
        emit_b(0xA9);
    }
    else {
        emit_b(0xF7);
        emit_b(0xC0 | reg);
    }
    emit_dw(imm);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_TEST).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::test(fuku_register reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x85);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_TEST).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::test_b(fuku_register reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x84);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_TEST).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::test(fuku_operand86& op, fuku_immediate& imm) {
    if (op.is_reg_only()) {     
        return test(op.get_reg(), imm);
    }
    if (imm.is_imm_8()) {
        return test_b(op, imm);
    }
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_register::r_EAX, op);
    emit_dw(imm);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_TEST).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::test_b(fuku_register reg, fuku_immediate& imm8) {
    clear_space();
    if (reg == fuku_register::r_EAX) {
        emit_b(0xA8);
        emit_b(imm8);
    }
    else {
        emit_b(0x66);
        emit_b(0xF7);
        emit_b(0xC0 | reg);
        emit_w(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_TEST).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::test_b(fuku_register dst, fuku_register src) {
    return test_b(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::test_b(fuku_operand86& op, fuku_immediate& imm8) {
    if (op.is_reg_only()) {
        return test_b(op.get_reg(), imm8);
    }
    clear_space();
    emit_b(0xF6);
    emit_operand(fuku_register::r_EAX, op);
    emit_b(imm8);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_TEST).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::test_w(fuku_register reg, fuku_immediate& imm16) {
    clear_space();
    if (reg == fuku_register::r_EAX) {
        emit_b(0xA9);
        emit_w(imm16);
    }
    else {
        emit_b(0x66);
        emit_b(0xF7);
        emit_b(0xC0 | reg);
        emit_w(imm16);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_TEST).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::test_w(fuku_register reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x66);
    emit_b(0x85);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_TEST).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::test_w(fuku_operand86& op, fuku_register reg) { 
    return test_w(reg, op); 
}

fuku_instruction fuku_asm_x86::test_w(fuku_register dst, fuku_register src) { 
    return test_w(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::test_w(fuku_operand86& op, fuku_immediate& imm16) {
    if (op.is_reg_only()) {
        return test_w(op.get_reg(), imm16);
    }
    clear_space();
    emit_b(0x66);
    emit_b(0xF7);
    emit_operand(fuku_register::r_EAX, op);
    emit_w(imm16);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_TEST).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::bt(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xA3);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_BT).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::bts(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAB);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_BTS).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::bsr(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xBD);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_BSR).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_CF);
}

fuku_instruction fuku_asm_x86::bsf(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xBC);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_BSF).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_CF);
}






*/
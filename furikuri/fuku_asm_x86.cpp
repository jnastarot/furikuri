#include "stdafx.h"
#include "fuku_asm_x86.h"



void fuku_operand86::set_modrm(int mod, fuku_register rm) {
    raw_operand[0] = (mod << 6) | fuku_get_index_reg(rm);
    operand_size = 1;
}

void fuku_operand86::set_sib(fuku_operand_scale scale, fuku_register index, fuku_register base) {
    raw_operand[1] = (scale << 6) | (fuku_get_index_reg(index) << 3) | fuku_get_index_reg(base);
    operand_size = 2;
}

void fuku_operand86::set_disp8(int8_t disp) {
    raw_operand[operand_size] = disp;
    disp_offset = operand_size;
    operand_size += sizeof(int8_t);
}
void fuku_operand86::set_dispr(int32_t disp) {
    *(int32_t*)&raw_operand[operand_size] = disp;
    disp_offset = operand_size;
    operand_size += sizeof(int32_t);
}

fuku_operand86::fuku_operand86(fuku_register reg) { 
    operand_size = 0; 
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

    set_modrm(3, reg); 
}

fuku_operand86::fuku_operand86(uint32_t disp) {
    operand_size = 0; 
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

    set_modrm(0, FUKU_REG_EBP);
    set_dispr(disp);
}

fuku_operand86::fuku_operand86(fuku_register base, uint32_t disp) {
    operand_size = 0;
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

    // [base + disp/r]
    if (disp == 0 && fuku_get_index_reg(base) != fuku_get_index_reg(FUKU_REG_EBP) ) {
        
        // [base]
        set_modrm(0, base);
        if (fuku_get_index_reg(base) == fuku_get_index_reg(FUKU_REG_ESP)) {
            set_sib(FUKU_OPERAND_SCALE_1, FUKU_REG_ESP, base);
        }
    }
    else if (!(disp&0xFFFFFF00)) {

        // [base + disp8]
        set_modrm(1, base);
        if (fuku_get_index_reg(base) == fuku_get_index_reg(FUKU_REG_ESP)) {
            set_sib(FUKU_OPERAND_SCALE_1, FUKU_REG_ESP, base);
        }
        set_disp8(disp);
    }
    else {
        
        // [base + disp/r]
        set_modrm(2, base);
        if (fuku_get_index_reg(base) == fuku_get_index_reg(FUKU_REG_ESP)) {
            set_sib(FUKU_OPERAND_SCALE_1, FUKU_REG_ESP, base);
        }
        set_dispr(disp);
    }
}

fuku_operand86::fuku_operand86(fuku_register base, fuku_register index, fuku_operand_scale scale, uint32_t disp) {
    operand_size = 0; 
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

 
    FUKU_ASSERT(fuku_get_index_reg(index) != fuku_get_index_reg(FUKU_REG_ESP));

    // [base + index*scale + disp/r]
    if (disp == 0 && base != fuku_register::r_EBP) {
        // [base + index*scale]
        set_modrm(0, fuku_register::r_ESP);
        set_sib(scale, index, base);
    }
    else if (!(disp & 0xFFFFFF00)) {
        // [base + index*scale + disp8]
        set_modrm(1, fuku_register::r_ESP);
        set_sib(scale, index, base);
        set_disp8(disp);
    }
    else {
        // [base + index*scale + disp/r]
        set_modrm(2, fuku_register::r_ESP);
        set_sib(scale, index, base);
        set_dispr(disp);
    }
}

fuku_operand86::fuku_operand86(fuku_register index, fuku_operand_scale scale, uint32_t disp) {
    operand_size = 0; 
    disp_offset = 0;
    memset(raw_operand, 0, sizeof(raw_operand)); 

    FUKU_ASSERT(fuku_get_index_reg(index) != fuku_get_index_reg(FUKU_REG_ESP));

    // [index*scale + disp/r]
    set_modrm(0, FUKU_REG_ESP);
    set_sib(scale, index, FUKU_REG_EBP);
    set_dispr(disp);
}

fuku_register fuku_operand86::get_register() const {
    FUKU_ASSERT(is_register_only());
    return fuku_register(raw_operand[0] & 0x07);
}
bool fuku_operand86::is_register_only() const {
    return (raw_operand[0] & 0xF8) == 0xC0;
}
const uint8_t* fuku_operand86::get_buf() const {
    return this->raw_operand;
}
uint8_t fuku_operand86::get_length() const {
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
    this->imm_offset = 0;
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
void fuku_asm_x86::emit_b(const fuku_immediate& x) {
    bytecode[length] = x.get_imm()&0xFF;
    length++;
}
void fuku_asm_x86::emit_w(const fuku_immediate& x) {
    *(uint16_t*)&bytecode[length] = x.get_imm()&0xFFFF;
    length += sizeof(uint16_t);
}
void fuku_asm_x86::emit_dw(const fuku_immediate& x) {
    *(uint32_t*)&bytecode[length] = x.get_imm();
    length += sizeof(uint32_t);
}

void fuku_asm_x86::emit_arith(int sel, fuku_operand86& dst, const fuku_immediate& x) {

    if ( std::abs((int32_t)x.get_imm()) < 128 ) {
        emit_b(0x83);
        emit_operand(fuku_register(sel), dst);
        emit_b((int32_t)x.get_imm());
    }
    else if (dst.get_reg() == fuku_register::r_EAX) {
        emit_b((sel << 3) | 0x05);
        emit_dw(x);
    }
    else {
        emit_b(0x81);
        emit_operand(fuku_register(sel), dst);
        emit_dw(x);
    }
}

void fuku_asm_x86::emit_operand(fuku_register reg, fuku_operand86& adr) {
    const unsigned _length = adr.get_length();

    bytecode[length] = (adr.get_buf()[0] & ~0x38) | (reg << 3);

    for (unsigned i = 1; i < _length; i++) { bytecode[length + i] = adr.get_buf()[i]; }
    
    if (adr.get_disp_offset()) {
        this->imm_offset = length + adr.get_disp_offset();
    }

    length += _length;
}

fuku_instruction fuku_asm_x86::pushad() {
    clear_space();
    emit_b(0x60);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_PUSHAL).set_eflags(0);
}

fuku_instruction fuku_asm_x86::popad() {
    clear_space();
    emit_b(0x61);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_POPAL).set_eflags(0);
}

fuku_instruction fuku_asm_x86::jmp(fuku_register reg) { 
    return jmp(fuku_operand86(reg)); 
}

fuku_instruction fuku_asm_x86::jmp(fuku_operand86& adr) {
    clear_space();
    emit_b(0xFF);
    emit_operand(fuku_register::r_ESP, adr);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_JMP).set_eflags(0);
}

fuku_instruction fuku_asm_x86::jmp(uint32_t offset) {
    clear_space();
    emit_b(0xE9);
    emit_dw(offset);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_JMP).set_eflags(0);
}
fuku_instruction fuku_asm_x86::jcc(fuku_condition cond, uint32_t offset) {
    clear_space();
    emit_b(0x0F);
    emit_b(0x80 | cond);
    emit_dw(offset);

    uint16_t di_jcc[] = {
        X86_INS_JO , X86_INS_JNO ,
        X86_INS_JB , X86_INS_JAE ,
        X86_INS_JE, X86_INS_JNE,
        X86_INS_JBE , X86_INS_JA ,
        X86_INS_JS , X86_INS_JNS ,
        X86_INS_JP , X86_INS_JNP ,
        X86_INS_JL , X86_INS_JGE ,
        X86_INS_JLE , X86_INS_JG ,
    };

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

    return fuku_instruction().set_op_code(bytecode, length).set_id(di_jcc[cond]).set_eflags(di_fl_jcc[cond]);
}

fuku_instruction fuku_asm_x86::cpuid() {
    clear_space();
    emit_b(0x0F);
    emit_b(0xA2);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CPUID).set_eflags(0);
}

fuku_instruction fuku_asm_x86::pushfd() {
    clear_space();
    emit_b(0x9C);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_PUSHF).set_eflags(0);
}


fuku_instruction fuku_asm_x86::popfd() {
    clear_space();
    emit_b(0x9D);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_POPF).set_eflags(0);
}


fuku_instruction fuku_asm_x86::push( fuku_immediate& x) {
    clear_space();
    if (x.is_imm_8()) {
        emit_b(0x6A);
        emit_b(x);
    }
    else {
        emit_b(0x68);
        emit_dw(x);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_PUSH).set_eflags(0);
}


fuku_instruction fuku_asm_x86::push_imm32(int32_t imm32) {
    clear_space();
    emit_b(0x68);
    emit_dw(imm32);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_PUSH).set_eflags(0);
}


fuku_instruction fuku_asm_x86::push(fuku_register src) {
    clear_space();
    emit_b(0x50 | src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_PUSH).set_eflags(0);
}

fuku_instruction fuku_asm_x86::push(fuku_operand86& src) {
    clear_space();
    emit_b(0xFF);
    emit_operand(fuku_register::r_ESI, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_PUSH).set_eflags(0);
}


fuku_instruction fuku_asm_x86::pop(fuku_register dst) {
    clear_space();
    emit_b(0x58 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_POP).set_eflags(0);
}

fuku_instruction fuku_asm_x86::pop(fuku_operand86& dst) {
    clear_space();
    emit_b(0x8F);
    emit_operand(fuku_register::r_EAX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_POP).set_eflags(0);
}


fuku_instruction fuku_asm_x86::enter( fuku_immediate& size) {
    clear_space();
    emit_b(0xC8);
    emit_w(size);
    emit_b(0);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ENTER).set_eflags(0);
}


fuku_instruction fuku_asm_x86::leave() {
    clear_space();
    emit_b(0xC9);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_LEAVE).set_eflags(0);
}

fuku_instruction fuku_asm_x86::mov_b(fuku_register dst, fuku_register src) { 
    return mov_b(dst, fuku_operand86(src)); 
}

fuku_instruction fuku_asm_x86::mov_b(fuku_register dst, int8_t imm8) { 
    return mov_b(fuku_operand86(dst), fuku_immediate(imm8)); 
}

fuku_instruction fuku_asm_x86::mov_b(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x8A);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}

fuku_instruction fuku_asm_x86::mov_b(fuku_operand86& dst,  fuku_immediate& src) {
    clear_space();
    emit_b(0xC6);
    emit_operand(fuku_register::r_EAX, dst);
    emit_b(src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}

fuku_instruction fuku_asm_x86::mov_b(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x88);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}

fuku_instruction fuku_asm_x86::mov_w(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x66);
    emit_b(0x8B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}

fuku_instruction fuku_asm_x86::mov_w(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x66);
    emit_b(0x89);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}

fuku_instruction fuku_asm_x86::mov_w(fuku_operand86& dst, fuku_immediate& src) {
    clear_space();
    emit_b(0x66);
    emit_b(0xC7);
    emit_operand(fuku_register::r_EAX, dst);
    emit_b(int8_t(src.get_imm() & 0xFF));
    emit_b(int8_t(src.get_imm() >> 8));
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}


fuku_instruction fuku_asm_x86::mov(fuku_register dst, int32_t imm32) {
    clear_space();
    emit_b(0xB8 | dst);
    emit_dw(imm32);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}


fuku_instruction fuku_asm_x86::mov(fuku_register dst, fuku_immediate& x) {
    clear_space();
    emit_b(0xB8 | dst);
    emit_dw(x);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}


fuku_instruction fuku_asm_x86::mov(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x8B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}


fuku_instruction fuku_asm_x86::mov(fuku_register dst, fuku_register src) {
    clear_space();
    emit_b(0x89);
    emit_b(0xC0 | src << 3 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}

fuku_instruction fuku_asm_x86::mov(fuku_operand86& dst, fuku_immediate& x) {
    clear_space();
    emit_b(0xC7);
    emit_operand(fuku_register::r_EAX, dst);
    emit_dw(x);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}

fuku_instruction fuku_asm_x86::mov(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x89);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOV).set_eflags(0);
}

fuku_instruction fuku_asm_x86::movsx_b(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xBE);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOVSX).set_eflags(0);
}

fuku_instruction fuku_asm_x86::movsx_w(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xBF);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOVSX).set_eflags(0);
}

fuku_instruction fuku_asm_x86::movzx_b(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xB6);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOVZX).set_eflags(0);
}

fuku_instruction fuku_asm_x86::movzx_w(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xB7);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOVZX).set_eflags(0);
}


fuku_instruction fuku_asm_x86::cld() {
    clear_space();
    emit_b(0xFC);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CLD).set_eflags(X86_EFLAGS_RESET_DF);
}


fuku_instruction fuku_asm_x86::rep_movs() {
    clear_space();
    emit_b(0xF3);
    emit_b(0xA5);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MOVSB).set_eflags(0);
}


fuku_instruction fuku_asm_x86::rep_stos() {
    clear_space();
    emit_b(0xF3);
    emit_b(0xAB);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_STOSB).set_eflags(0);
}


fuku_instruction fuku_asm_x86::stos() {
    clear_space();
    emit_b(0xAB);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_STOSB).set_eflags(0);
}


fuku_instruction fuku_asm_x86::xchg(fuku_register dst, fuku_register src) {
    clear_space();
    if (src == fuku_register::r_EAX || dst == fuku_register::r_EAX) {  // Single-byte encoding.
        emit_b(0x90 | (src == fuku_register::r_EAX ? dst : src));
    }
    else {
        emit_b(0x87);
        emit_b(0xC0 | src << 3 | dst);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_XCHG).set_eflags(0);
}

fuku_instruction fuku_asm_x86::xchg(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x87);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_XCHG).set_eflags(0);
}

fuku_instruction fuku_asm_x86::xchg_b(fuku_register reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x86);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_XCHG).set_eflags(0);
}

fuku_instruction fuku_asm_x86::xchg_w(fuku_register reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x66);
    emit_b(0x87);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_XCHG).set_eflags(0);
}

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

fuku_instruction fuku_asm_x86::lfence() {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAE);
    emit_b(0xE8);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_LFENCE).set_eflags(0);
}

fuku_instruction fuku_asm_x86::pause() {
    clear_space();
    emit_b(0xF3);
    emit_b(0x90);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_PAUSE).set_eflags(0);
}

fuku_instruction fuku_asm_x86::adc(fuku_register dst, int32_t imm32) {
    clear_space();
    emit_arith(2, fuku_operand86(dst), fuku_immediate(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ADC).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::adc(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x13);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ADC).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::add(fuku_register dst, fuku_register src) {
    return add(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::add(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x03);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ADD).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::add(fuku_register dst, fuku_immediate& imm) { 
    return add(fuku_operand86(dst), imm);
}

fuku_instruction fuku_asm_x86::add(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x01);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ADD).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::add(fuku_operand86& dst, fuku_immediate& x) {
    clear_space();
    emit_arith(0, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_ADD).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}


fuku_instruction fuku_asm_x86::and(fuku_register dst, int32_t imm32) {
    and(dst, fuku_immediate(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_AND).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::and(fuku_register dst, fuku_register src) {
    return and(dst, fuku_operand86(src));
}


fuku_instruction fuku_asm_x86::and(fuku_register dst, fuku_immediate& x) {
    clear_space();
    emit_arith(4, fuku_operand86(dst), x);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_AND).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::and(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x23);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_AND).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::and(fuku_operand86& dst, fuku_immediate& x) {
    clear_space();
    emit_arith(4, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_AND).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::and(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x21);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_AND).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::cmpb(fuku_register dst, fuku_register src) { 
    return cmpb(fuku_operand86(dst), src); 
}

fuku_instruction fuku_asm_x86::cmpb(fuku_register reg, fuku_immediate& imm8) {
    return cmpb(fuku_operand86(reg), imm8); 
}

fuku_instruction fuku_asm_x86::cmpb(fuku_operand86& op, fuku_immediate& imm8) {
    clear_space();
    if (op.get_reg() == (fuku_register::r_EAX)) {
        emit_b(0x3C);
    }
    else {
        emit_b(0x80);
        emit_operand(fuku_register::r_EDI, op);  // edi == 7
    }
    emit_b(imm8);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmpb(fuku_operand86& op, fuku_register reg) {
    clear_space();
    emit_b(0x38);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmpb(fuku_register reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x3A);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmpw(fuku_register dst, fuku_immediate& src) { 
    return cmpw(fuku_operand86(dst), src); 
}

fuku_instruction fuku_asm_x86::cmpw(fuku_register dst, fuku_register src) { 
    return cmpw(fuku_operand86(dst), src); 
}

fuku_instruction fuku_asm_x86::cmpw(fuku_operand86& op, fuku_immediate& imm16) {
    clear_space();
    emit_b(0x66);
    emit_b(0x81);
    emit_operand(fuku_register::r_EDI, op);
    emit_w(imm16);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmpw(fuku_register reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x66);
    emit_b(0x3B);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmpw(fuku_operand86& op, fuku_register reg) {
    clear_space();
    emit_b(0x66);
    emit_b(0x39);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmp(fuku_register reg0, fuku_register reg1) { 
    return cmp(reg0, fuku_operand86(reg1)); 
}

fuku_instruction fuku_asm_x86::cmp(fuku_register reg, fuku_immediate& imm) { 
    return cmp(fuku_operand86(reg), imm); 
}

fuku_instruction fuku_asm_x86::cmp(fuku_register reg, int32_t imm32) {
    clear_space();
    emit_arith(7, fuku_operand86(reg), fuku_immediate(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmp(fuku_register reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x3B);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmp(fuku_operand86& op, fuku_register reg) {
    clear_space();
    emit_b(0x39);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmp(fuku_operand86& op, fuku_immediate& imm) {
    clear_space();
    emit_arith(7, op, imm);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmpb_al(fuku_operand86& op) {
    clear_space();
    emit_b(0x38);  // CMP r/m8, r8
    emit_operand(fuku_register::r_EAX, op);  // eax has same code as register al.
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::cmpw_ax(fuku_operand86& op) {
    clear_space();
    emit_b(0x66);
    emit_b(0x39);  // CMP r/m16, r16
    emit_operand(fuku_register::r_EAX, op);  // eax has same code as register ax.
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CMP).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}


fuku_instruction fuku_asm_x86::dec_b(fuku_register dst) {
    clear_space();
    emit_b(0xFE);
    emit_b(0xC8 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_DEC).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF);
}

fuku_instruction fuku_asm_x86::dec_b(fuku_operand86& dst) {
    clear_space();
    emit_b(0xFE);
    emit_operand(fuku_register::r_ECX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_DEC).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF);
}


fuku_instruction fuku_asm_x86::dec(fuku_register dst) {
    clear_space();
    emit_b(0x48 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_DEC).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF);
}

fuku_instruction fuku_asm_x86::dec(fuku_operand86& dst) {
    clear_space();
    emit_b(0xFF);
    emit_operand(fuku_register::r_ECX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_DEC).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF);
}


fuku_instruction fuku_asm_x86::cdq() {
    clear_space();
    emit_b(0x99);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_CDQ).set_eflags(0);
}

fuku_instruction fuku_asm_x86::idiv(fuku_operand86& src) {
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_register::r_EDI, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_IDIV).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_CF);
}

fuku_instruction fuku_asm_x86::div(fuku_operand86& src) {
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_register::r_ESI, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_DIV).set_eflags(X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_CF);
}


fuku_instruction fuku_asm_x86::imul(fuku_register reg) {
    clear_space();
    emit_b(0xF7);
    emit_b(0xE8 | reg);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_IMUL).set_eflags(X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF);
}

fuku_instruction fuku_asm_x86::imul(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAF);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_IMUL).set_eflags(X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF);
}


fuku_instruction fuku_asm_x86::imul(fuku_register dst, fuku_register src, int32_t imm32) {
    imul(dst, fuku_operand86(src), imm32);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_IMUL).set_eflags(X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF);
}

fuku_instruction fuku_asm_x86::imul(fuku_register dst, fuku_operand86& src, int32_t imm32) {
    clear_space();
    if (!(imm32&0xFFFFFF00)) {
        emit_b(0x6B);
        emit_operand(dst, src);
        emit_b(imm32);
    }
    else {
        emit_b(0x69);
        emit_operand(dst, src);
        emit_dw(imm32);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_IMUL).set_eflags(X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF);
}


fuku_instruction fuku_asm_x86::inc(fuku_register dst) {
    clear_space();
    emit_b(0x40 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_INC).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF);
}

fuku_instruction fuku_asm_x86::inc(fuku_operand86& dst) {
    clear_space();
    emit_b(0xFF);
    emit_operand(fuku_register::r_EAX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_INC).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF);
}

fuku_instruction fuku_asm_x86::lea(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x8D);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_LEA).set_eflags(0);
}


fuku_instruction fuku_asm_x86::mul(fuku_register src) {
    clear_space();
    emit_b(0xF7);
    emit_b(0xE0 | src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_MUL).set_eflags(X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_OF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_PF);
}


fuku_instruction fuku_asm_x86::neg(fuku_register dst) {
    clear_space();
    emit_b(0xF7);
    emit_b(0xD8 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NEG).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::neg(fuku_operand86& dst) {
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_register::r_EBX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NEG).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}


fuku_instruction fuku_asm_x86::not(fuku_register dst) {
    clear_space();
    emit_b(0xF7);
    emit_b(0xD0 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NOT).set_eflags(0);
}

fuku_instruction fuku_asm_x86::not(fuku_operand86& dst) {
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_register::r_EDX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NOT).set_eflags(0);
}

fuku_instruction fuku_asm_x86::or(fuku_register dst, fuku_register src) {
    return or(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::or(fuku_register dst, int32_t imm32) {
    clear_space();
    emit_arith(1, fuku_operand86(dst), fuku_immediate(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_OR).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::or(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_OR).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::or(fuku_operand86& dst, fuku_immediate& x) {
    clear_space();
    emit_arith(1, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_OR).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::or(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x09);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_OR).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
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


fuku_instruction fuku_asm_x86::sbb(fuku_register dst, fuku_register src) { 
    return sbb(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::sbb(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x1B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SBB).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
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

fuku_instruction fuku_asm_x86::sub(fuku_register dst, fuku_immediate& x) { 
   return sub(fuku_operand86(dst), x);
}

fuku_instruction fuku_asm_x86::sub(fuku_register dst, fuku_register src) {
    return sub(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::sub(fuku_operand86& dst, fuku_immediate& x) {
    clear_space();
    emit_arith(5, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SUB).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::sub(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x2B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SUB).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
}

fuku_instruction fuku_asm_x86::sub(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x29);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_SUB).set_eflags(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF);
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

fuku_instruction fuku_asm_x86::xor(fuku_register dst, fuku_register src) {
    return xor(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::xor(fuku_register dst, int32_t imm32) {
    clear_space();
    emit_arith(6, fuku_operand86(dst), fuku_immediate(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_XOR).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::xor(fuku_register dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x33);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_XOR).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::xor(fuku_operand86& dst, fuku_register src) {
    clear_space();
    emit_b(0x31);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_XOR).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
}

fuku_instruction fuku_asm_x86::xor(fuku_operand86& dst, fuku_immediate& x) {
    clear_space();
    emit_arith(6, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_XOR).set_eflags(X86_EFLAGS_RESET_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_CF);
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


fuku_instruction fuku_asm_x86::hlt() {
    clear_space();
    emit_b(0xF4);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_HLT).set_eflags(0);
}


fuku_instruction fuku_asm_x86::int3() {
    clear_space();
    emit_b(0xCC);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_INT3).set_eflags(0);
}


fuku_instruction fuku_asm_x86::nop() {
    clear_space();
    emit_b(0x90);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_NOP).set_eflags(0);
}


fuku_instruction fuku_asm_x86::ret(int imm16) {
    clear_space();
    if (imm16 == 0) {
        emit_b(0xC3);
    }
    else {
        emit_b(0xC2);
        emit_b(imm16 & 0xFF);
        emit_b((imm16 >> 8) & 0xFF);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_RET).set_eflags(0);
}


fuku_instruction fuku_asm_x86::ud2() {
    clear_space();
    emit_b(0x0F);
    emit_b(0x0B);
    return fuku_instruction().set_op_code(bytecode, length).set_id(X86_INS_UD2).set_eflags(0);
}

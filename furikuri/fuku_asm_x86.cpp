#include "stdafx.h"
#include "fuku_asm_x86.h"



fuku_immediate86::fuku_immediate86()
:imm_value(0){}

fuku_immediate86::fuku_immediate86(uint32_t imm)
:imm_value(imm) {}

fuku_immediate86::~fuku_immediate86() {};

void fuku_immediate86::set_imm(uint32_t imm) {
    this->imm_value = imm;
}

bool fuku_immediate86::is_imm_8() const {
    return !(imm_value & 0xFFFFFF00);
}
bool fuku_immediate86::is_imm_16() const {
    return (imm_value & 0xFFFF0000) == 0;
}
bool fuku_immediate86::is_imm_32() const {
    return (imm_value & 0xFFFF0000) != 0;
}

uint32_t fuku_immediate86::get_imm() const{
    return imm_value;
}

void fuku_operand86::set_modrm(int mod, fuku_reg86 rm) {
    buf[0] = (mod << 6) | rm;
    len = 1;
}

void fuku_operand86::set_sib(operand_scale scale, fuku_reg86 index, fuku_reg86 base) {
    buf[1] = (scale << 6) | (index << 3) | base;
    len = 2;
}

void fuku_operand86::set_disp8(int8_t disp) {
    buf[len] = disp;
    disp_offset = len;
    len += sizeof(int8_t);
}
void fuku_operand86::set_dispr(int32_t disp) {
    *(int32_t*)&buf[len] = disp;
    disp_offset = len;
    len += sizeof(int32_t);
}

fuku_operand86::fuku_operand86(fuku_reg86 reg) { 
    len = 0; memset(buf, 0, sizeof(buf)); disp_offset = 0;
    set_modrm(3, reg); 
}

fuku_operand86::fuku_operand86(uint32_t disp) {
    len = 0; memset(buf, 0, sizeof(buf)); disp_offset = 0;
    set_modrm(0, fuku_reg86::r_EBP);
    set_dispr(disp);
}

fuku_operand86::fuku_operand86(fuku_reg86 base, uint32_t disp) {
    len = 0; memset(buf, 0, sizeof(buf)); disp_offset = 0;

    // [base + disp/r]
    if (disp == 0 && base != fuku_reg86::r_EBP) {
        // [base]
        set_modrm(0, base);
        if (base == fuku_reg86::r_ESP) { set_sib(operand_scale_1, fuku_reg86::r_ESP, base); }
    }
    else if (!(disp&0xFFFFFF00)) {
        // [base + disp8]
        set_modrm(1, base);
        if (base == fuku_reg86::r_ESP) { set_sib(operand_scale_1, fuku_reg86::r_ESP, base); }
        set_disp8(disp);
    }
    else {
        // [base + disp/r]
        set_modrm(2, base);
        if (base == fuku_reg86::r_ESP) { set_sib(operand_scale_1, fuku_reg86::r_ESP, base); }
        set_dispr(disp);
    }
}

fuku_operand86::fuku_operand86(fuku_reg86 base, fuku_reg86 index, operand_scale scale, uint32_t disp) {
    len = 0; memset(buf, 0, sizeof(buf)); disp_offset = 0;

    // [base + index*scale + disp/r]
    if (disp == 0 && base != fuku_reg86::r_EBP) {
        // [base + index*scale]
        set_modrm(0, fuku_reg86::r_ESP);
        set_sib(scale, index, base);
    }
    else if (!(disp & 0xFFFFFF00)) {
        // [base + index*scale + disp8]
        set_modrm(1, fuku_reg86::r_ESP);
        set_sib(scale, index, base);
        set_disp8(disp);
    }
    else {
        // [base + index*scale + disp/r]
        set_modrm(2, fuku_reg86::r_ESP);
        set_sib(scale, index, base);
        set_dispr(disp);
    }
}

fuku_operand86::fuku_operand86(fuku_reg86 index, operand_scale scale, uint32_t disp) {
    len = 0; memset(buf, 0, sizeof(buf)); disp_offset = 0;

    // [index*scale + disp/r]
    set_modrm(0, fuku_reg86::r_ESP);
    set_sib(scale, index, fuku_reg86::r_EBP);
    set_dispr(disp);
}

fuku_reg86 fuku_operand86::get_reg() const {
    return fuku_reg86(buf[0] & 0x07);
}
bool fuku_operand86::is_reg_only() const {
    return (buf[0] & 0xF8) == 0xC0;  
}
const uint8_t* fuku_operand86::get_buf() const {
    return this->buf;
}
uint8_t fuku_operand86::get_length() const {
    return this->len;
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
void fuku_asm_x86::emit_b(const fuku_immediate86& x) {
    bytecode[length] = x.get_imm()&0xFF;
    length++;
}
void fuku_asm_x86::emit_w(const fuku_immediate86& x) {
    *(uint16_t*)&bytecode[length] = x.get_imm()&0xFFFF;
    length += sizeof(uint16_t);
}
void fuku_asm_x86::emit_dw(const fuku_immediate86& x) {
    *(uint32_t*)&bytecode[length] = x.get_imm();
    length += sizeof(uint32_t);
}

void fuku_asm_x86::emit_arith(int sel, fuku_operand86& dst, const fuku_immediate86& x) {

    if ( std::abs((int32_t)x.get_imm()) < 128 ) {
        emit_b(0x83);
        emit_operand(fuku_reg86(sel), dst);
        emit_b((int32_t)x.get_imm());
    }
    else if (dst.get_reg() == fuku_reg86::r_EAX) {
        emit_b((sel << 3) | 0x05);
        emit_dw(x);
    }
    else {
        emit_b(0x81);
        emit_operand(fuku_reg86(sel), dst);
        emit_dw(x);
    }
}

void fuku_asm_x86::emit_operand(fuku_reg86 reg, fuku_operand86& adr) {
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
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_PUSHA).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::popad() {
    clear_space();
    emit_b(0x61);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_POPA).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::jmp(fuku_reg86 reg) { 
    return jmp(fuku_operand86(reg)); 
}

fuku_instruction fuku_asm_x86::jmp(fuku_operand86& adr) {
    clear_space();
    emit_b(0xFF);
    emit_operand(fuku_reg86::r_ESP, adr);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_JMP).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::jmp(uint32_t offset) {
    clear_space();
    emit_b(0xE9);
    emit_dw(offset);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_JMP).set_modified_flags(0).set_tested_flags(0);
}
fuku_instruction fuku_asm_x86::jcc(fuku_condition cond, uint32_t offset) {
    clear_space();
    emit_b(0x0F);
    emit_b(0x80 | cond);
    emit_dw(offset);

    uint8_t di_jcc[] = { 134 , 138 , 143 , 147 , 152 , 156 , 161 , 166 , 170 , 174 , 179 , 183 , 188 , 192 , 197 , 202 };

    uint16_t di_fl_jcc[] = {
        D_OF , D_OF ,
        D_CF , D_CF ,
        D_ZF , D_ZF ,
        D_CF | D_ZF, D_CF | D_ZF ,
        D_SF , D_SF ,
        D_PF , D_PF ,
        D_SF | D_OF, D_SF | D_OF ,
        D_ZF | D_SF | D_OF, D_ZF | D_SF | D_OF
    };

    return fuku_instruction().set_op_code(bytecode, length).set_type(di_jcc[cond]).set_modified_flags(0).set_tested_flags(di_fl_jcc[cond]);
}

fuku_instruction fuku_asm_x86::cpuid() {
    clear_space();
    emit_b(0x0F);
    emit_b(0xA2);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CPUID).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::pushfd() {
    clear_space();
    emit_b(0x9C);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_PUSHF).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::popfd() {
    clear_space();
    emit_b(0x9D);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_POPF).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::push( fuku_immediate86& x) {
    clear_space();
    if (x.is_imm_8()) {
        emit_b(0x6A);
        emit_b(x);
    }
    else {
        emit_b(0x68);
        emit_dw(x);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_PUSH).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::push_imm32(int32_t imm32) {
    clear_space();
    emit_b(0x68);
    emit_dw(imm32);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_PUSH).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::push(fuku_reg86 src) {
    clear_space();
    emit_b(0x50 | src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_PUSH).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::push(fuku_operand86& src) {
    clear_space();
    emit_b(0xFF);
    emit_operand(fuku_reg86::r_ESI, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_PUSH).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::pop(fuku_reg86 dst) {
    clear_space();
    emit_b(0x58 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_POP).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::pop(fuku_operand86& dst) {
    clear_space();
    emit_b(0x8F);
    emit_operand(fuku_reg86::r_EAX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_POP).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::enter( fuku_immediate86& size) {
    clear_space();
    emit_b(0xC8);
    emit_w(size);
    emit_b(0);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ENTER).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::leave() {
    clear_space();
    emit_b(0xC9);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_LEAVE).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::mov_b(fuku_reg86 dst, fuku_reg86 src) { 
    return mov_b(dst, fuku_operand86(src)); 
}

fuku_instruction fuku_asm_x86::mov_b(fuku_reg86 dst, int8_t imm8) { 
    return mov_b(fuku_operand86(dst), fuku_immediate86(imm8)); 
}

fuku_instruction fuku_asm_x86::mov_b(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x8A);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::mov_b(fuku_operand86& dst,  fuku_immediate86& src) {
    clear_space();
    emit_b(0xC6);
    emit_operand(fuku_reg86::r_EAX, dst);
    emit_b(src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::mov_b(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x88);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::mov_w(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x66);
    emit_b(0x8B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::mov_w(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x66);
    emit_b(0x89);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::mov_w(fuku_operand86& dst, fuku_immediate86& src) {
    clear_space();
    emit_b(0x66);
    emit_b(0xC7);
    emit_operand(fuku_reg86::r_EAX, dst);
    emit_b(int8_t(src.get_imm() & 0xFF));
    emit_b(int8_t(src.get_imm() >> 8));
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::mov(fuku_reg86 dst, int32_t imm32) {
    clear_space();
    emit_b(0xB8 | dst);
    emit_dw(imm32);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::mov(fuku_reg86 dst, fuku_immediate86& x) {
    clear_space();
    emit_b(0xB8 | dst);
    emit_dw(x);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::mov(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x8B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::mov(fuku_reg86 dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x89);
    emit_b(0xC0 | src << 3 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::mov(fuku_operand86& dst, fuku_immediate86& x) {
    clear_space();
    emit_b(0xC7);
    emit_operand(fuku_reg86::r_EAX, dst);
    emit_dw(x);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::mov(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x89);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOV).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::movsx_b(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xBE);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOVSX).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::movsx_w(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xBF);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOVSX).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::movzx_b(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xB6);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOVZX).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::movzx_w(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xB7);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOVZX).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::cld() {
    clear_space();
    emit_b(0xFC);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CLD).set_modified_flags(D_DF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::rep_movs() {
    clear_space();
    emit_b(0xF3);
    emit_b(0xA5);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MOVS).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::rep_stos() {
    clear_space();
    emit_b(0xF3);
    emit_b(0xAB);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_STOS).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::stos() {
    clear_space();
    emit_b(0xAB);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_STOS).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::xchg(fuku_reg86 dst, fuku_reg86 src) {
    clear_space();
    if (src == fuku_reg86::r_EAX || dst == fuku_reg86::r_EAX) {  // Single-byte encoding.
        emit_b(0x90 | (src == fuku_reg86::r_EAX ? dst : src));
    }
    else {
        emit_b(0x87);
        emit_b(0xC0 | src << 3 | dst);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_XCHG).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::xchg(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x87);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_XCHG).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::xchg_b(fuku_reg86 reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x86);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_XCHG).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::xchg_w(fuku_reg86 reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x66);
    emit_b(0x87);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_XCHG).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpxchg(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xB1);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMPXCHG).set_modified_flags(D_ZF | D_CF | D_PF | D_AF | D_SF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpxchg_b(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xB0);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMPXCHG8B).set_modified_flags(D_ZF | D_CF | D_PF | D_AF | D_SF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpxchg_w(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x66);
    emit_b(0x0F);
    emit_b(0xB1);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMPXCHG16B).set_modified_flags(D_ZF | D_CF | D_PF | D_AF | D_SF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::lfence() {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAE);
    emit_b(0xE8);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_LFENCE).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::pause() {
    clear_space();
    emit_b(0xF3);
    emit_b(0x90);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_PAUSE).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::adc(fuku_reg86 dst, int32_t imm32) {
    clear_space();
    emit_arith(2, fuku_operand86(dst), fuku_immediate86(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ADC).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::adc(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x13);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ADC).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::add(fuku_reg86 dst, fuku_reg86 src) {
    return add(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::add(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x03);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ADD).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::add(fuku_reg86 dst, fuku_immediate86& imm) { 
    return add(fuku_operand86(dst), imm);
}

fuku_instruction fuku_asm_x86::add(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x01);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ADD).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::add(fuku_operand86& dst, fuku_immediate86& x) {
    clear_space();
    emit_arith(0, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ADD).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::and_(fuku_reg86 dst, int32_t imm32) {
    and_(dst, fuku_immediate86(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_AND).set_modified_flags(D_OF | D_CF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::and_(fuku_reg86 dst, fuku_reg86 src) {
    return and_(dst, fuku_operand86(src));
}


fuku_instruction fuku_asm_x86::and_(fuku_reg86 dst, fuku_immediate86& x) {
    clear_space();
    emit_arith(4, fuku_operand86(dst), x);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_AND).set_modified_flags(D_OF | D_CF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::and_(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x23);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_AND).set_modified_flags(D_OF | D_CF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::and_(fuku_operand86& dst, fuku_immediate86& x) {
    clear_space();
    emit_arith(4, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_AND).set_modified_flags(D_OF | D_CF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::and_(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x21);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_AND).set_modified_flags(D_OF | D_CF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpb(fuku_reg86 dst, fuku_reg86 src) { 
    return cmpb(fuku_operand86(dst), src); 
}

fuku_instruction fuku_asm_x86::cmpb(fuku_reg86 reg, fuku_immediate86& imm8) {
    return cmpb(fuku_operand86(reg), imm8); 
}

fuku_instruction fuku_asm_x86::cmpb(fuku_operand86& op, fuku_immediate86& imm8) {
    clear_space();
    if (op.get_reg() == (fuku_reg86::r_EAX)) {
        emit_b(0x3C);
    }
    else {
        emit_b(0x80);
        emit_operand(fuku_reg86::r_EDI, op);  // edi == 7
    }
    emit_b(imm8);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpb(fuku_operand86& op, fuku_reg86 reg) {
    clear_space();
    emit_b(0x38);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpb(fuku_reg86 reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x3A);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpw(fuku_reg86 dst, fuku_immediate86& src) { 
    return cmpw(fuku_operand86(dst), src); 
}

fuku_instruction fuku_asm_x86::cmpw(fuku_reg86 dst, fuku_reg86 src) { 
    return cmpw(fuku_operand86(dst), src); 
}

fuku_instruction fuku_asm_x86::cmpw(fuku_operand86& op, fuku_immediate86& imm16) {
    clear_space();
    emit_b(0x66);
    emit_b(0x81);
    emit_operand(fuku_reg86::r_EDI, op);
    emit_w(imm16);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpw(fuku_reg86 reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x66);
    emit_b(0x3B);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpw(fuku_operand86& op, fuku_reg86 reg) {
    clear_space();
    emit_b(0x66);
    emit_b(0x39);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmp(fuku_reg86 reg0, fuku_reg86 reg1) { 
    return cmp(reg0, fuku_operand86(reg1)); 
}

fuku_instruction fuku_asm_x86::cmp(fuku_reg86 reg, fuku_immediate86& imm) { 
    return cmp(fuku_operand86(reg), imm); 
}

fuku_instruction fuku_asm_x86::cmp(fuku_reg86 reg, int32_t imm32) {
    clear_space();
    emit_arith(7, fuku_operand86(reg), fuku_immediate86(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmp(fuku_reg86 reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x3B);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmp(fuku_operand86& op, fuku_reg86 reg) {
    clear_space();
    emit_b(0x39);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmp(fuku_operand86& op, fuku_immediate86& imm) {
    clear_space();
    emit_arith(7, op, imm);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpb_al(fuku_operand86& op) {
    clear_space();
    emit_b(0x38);  // CMP r/m8, r8
    emit_operand(fuku_reg86::r_EAX, op);  // eax has same code as register al.
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::cmpw_ax(fuku_operand86& op) {
    clear_space();
    emit_b(0x66);
    emit_b(0x39);  // CMP r/m16, r16
    emit_operand(fuku_reg86::r_EAX, op);  // eax has same code as register ax.
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CMP).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::dec_b(fuku_reg86 dst) {
    clear_space();
    emit_b(0xFE);
    emit_b(0xC8 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_DEC).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::dec_b(fuku_operand86& dst) {
    clear_space();
    emit_b(0xFE);
    emit_operand(fuku_reg86::r_ECX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_DEC).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::dec(fuku_reg86 dst) {
    clear_space();
    emit_b(0x48 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_DEC).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::dec(fuku_operand86& dst) {
    clear_space();
    emit_b(0xFF);
    emit_operand(fuku_reg86::r_ECX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_DEC).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::cdq() {
    clear_space();
    emit_b(0x99);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_CDQ).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::idiv(fuku_operand86& src) {
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_reg86::r_EDI, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_IDIV).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::div(fuku_operand86& src) {
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_reg86::r_ESI, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_DIV).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::imul(fuku_reg86 reg) {
    clear_space();
    emit_b(0xF7);
    emit_b(0xE8 | reg);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_IMUL).set_modified_flags(D_CF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::imul(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAF);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_IMUL).set_modified_flags(D_CF | D_OF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::imul(fuku_reg86 dst, fuku_reg86 src, int32_t imm32) {
    imul(dst, fuku_operand86(src), imm32);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_IMUL).set_modified_flags(D_CF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::imul(fuku_reg86 dst, fuku_operand86& src, int32_t imm32) {
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
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_IMUL).set_modified_flags(D_CF | D_OF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::inc(fuku_reg86 dst) {
    clear_space();
    emit_b(0x40 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_INC).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::inc(fuku_operand86& dst) {
    clear_space();
    emit_b(0xFF);
    emit_operand(fuku_reg86::r_EAX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_INC).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::lea(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x8D);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_LEA).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::mul(fuku_reg86 src) {
    clear_space();
    emit_b(0xF7);
    emit_b(0xE0 | src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_MUL).set_modified_flags(D_OF | D_CF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::neg(fuku_reg86 dst) {
    clear_space();
    emit_b(0xF7);
    emit_b(0xD8 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_NEG).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::neg(fuku_operand86& dst) {
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_reg86::r_EBX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_NEG).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::not_(fuku_reg86 dst) {
    clear_space();
    emit_b(0xF7);
    emit_b(0xD0 | dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_NOT).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::not_(fuku_operand86& dst) {
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_reg86::r_EDX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_NOT).set_modified_flags(0).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::or_(fuku_reg86 dst, fuku_reg86 src) {
    return or_(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::or_(fuku_reg86 dst, int32_t imm32) {
    clear_space();
    emit_arith(1, fuku_operand86(dst), fuku_immediate86(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_OR).set_modified_flags(D_OF | D_CF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::or_(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_OR).set_modified_flags(D_OF | D_CF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::or_(fuku_operand86& dst, fuku_immediate86& x) {
    clear_space();
    emit_arith(1, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_OR).set_modified_flags(D_OF | D_CF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::or_(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x09);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_OR).set_modified_flags(D_OF | D_CF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::rcl(fuku_reg86 dst, uint8_t imm8) {
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
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_RCL).set_modified_flags(D_OF | D_CF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::rcr(fuku_reg86 dst, uint8_t imm8) {
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
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_RCR).set_modified_flags(D_OF | D_CF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::ror(fuku_reg86 dst, uint8_t imm8) { 
    return ror(fuku_operand86(dst), imm8);
}

fuku_instruction fuku_asm_x86::ror_cl(fuku_reg86 dst) { 
    return ror_cl(fuku_operand86(dst)); 
}

fuku_instruction fuku_asm_x86::ror(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_reg86::r_ECX, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_reg86::r_ECX, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ROR).set_modified_flags(D_OF | D_CF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::ror_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_reg86::r_ECX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ROR).set_modified_flags(D_OF | D_CF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::rol(fuku_reg86 dst, uint8_t imm8) {
    return rol(fuku_operand86(dst), imm8);
}

fuku_instruction fuku_asm_x86::rol_cl(fuku_reg86 dst) {
    return rol_cl(fuku_operand86(dst));
}

fuku_instruction fuku_asm_x86::rol(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_reg86::r_EAX, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_reg86::r_EAX, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ROL).set_modified_flags(D_OF | D_CF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::rol_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_reg86::r_EAX, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_ROL).set_modified_flags(D_OF | D_CF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::sar(fuku_reg86 dst, uint8_t imm8) { 
    return sar(fuku_operand86(dst), imm8);
}

fuku_instruction fuku_asm_x86::sar_cl(fuku_reg86 dst) { 
    return sar_cl(fuku_operand86(dst));
}

fuku_instruction fuku_asm_x86::sar(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_reg86::r_EDI, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_reg86::r_EDI, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SAR).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::sar_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_reg86::r_EDI, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SAR).set_modified_flags(D_CF | D_OF | D_SF | D_ZF | D_PF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::sbb(fuku_reg86 dst, fuku_reg86 src) { 
    return sbb(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::sbb(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x1B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SBB).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::shld(fuku_reg86 dst, fuku_reg86 src, uint8_t shift) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xA4);
    emit_operand(src, fuku_operand86(dst));
    emit_b(shift);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SHLD).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_AF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::shld_cl(fuku_reg86 dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xA5);
    emit_operand(src, fuku_operand86(dst));
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SHLD).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_AF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::shl(fuku_reg86 dst, uint8_t imm8) { 
    return shl(fuku_operand86(dst), imm8); 
}

fuku_instruction fuku_asm_x86::shl(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_reg86::r_ESP, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_reg86::r_ESP, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SHL).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::shl_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_reg86::r_ESP, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SHL).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::shr(fuku_operand86& dst, uint8_t imm8) {
    clear_space();
    if (imm8 == 1) {
        emit_b(0xD1);
        emit_operand(fuku_reg86::r_EBP, dst);
    }
    else {
        emit_b(0xC1);
        emit_operand(fuku_reg86::r_EBP, dst);
        emit_b(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SHR).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::shr_cl(fuku_operand86& dst) {
    clear_space();
    emit_b(0xD3);
    emit_operand(fuku_reg86::r_EBP, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SHR).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::shrd(fuku_reg86 dst, fuku_reg86 src, uint8_t shift) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAC);
    emit_operand(dst, fuku_operand86(src));
    emit_b(shift);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SHRD).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::shrd_cl(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAD);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SHRD).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::sub(fuku_reg86 dst, fuku_immediate86& x) { 
   return sub(fuku_operand86(dst), x);
}

fuku_instruction fuku_asm_x86::sub(fuku_reg86 dst, fuku_reg86 src) {
    return sub(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::sub(fuku_operand86& dst, fuku_immediate86& x) {
    clear_space();
    emit_arith(5, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SUB).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::sub(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x2B);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SUB).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::sub(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x29);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_SUB).set_modified_flags(D_OF | D_SF | D_ZF | D_AF | D_CF | D_PF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::test(fuku_reg86 reg0, fuku_reg86 reg1) { 
    return test(reg0, fuku_operand86(reg1)); 
}

fuku_instruction fuku_asm_x86::test(fuku_reg86 reg, fuku_immediate86& imm) {
    if (imm.is_imm_8()) {        
        return test_b(reg, imm);
    }

    clear_space();
    if (reg == fuku_reg86::r_EAX) {
        emit_b(0xA9);
    }
    else {
        emit_b(0xF7);
        emit_b(0xC0 | reg);
    }
    emit_dw(imm);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_TEST).set_modified_flags(D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::test(fuku_reg86 reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x85);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_TEST).set_modified_flags(D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::test_b(fuku_reg86 reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x84);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_TEST).set_modified_flags(D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::test(fuku_operand86& op, fuku_immediate86& imm) {
    if (op.is_reg_only()) {     
        return test(op.get_reg(), imm);
    }
    if (imm.is_imm_8()) {
        return test_b(op, imm);
    }
    clear_space();
    emit_b(0xF7);
    emit_operand(fuku_reg86::r_EAX, op);
    emit_dw(imm);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_TEST).set_modified_flags(D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::test_b(fuku_reg86 reg, fuku_immediate86& imm8) {
    clear_space();
    if (reg == fuku_reg86::r_EAX) {
        emit_b(0xA8);
        emit_b(imm8);
    }
    else {
        emit_b(0x66);
        emit_b(0xF7);
        emit_b(0xC0 | reg);
        emit_w(imm8);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_TEST).set_modified_flags(D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::test_b(fuku_reg86 dst, fuku_reg86 src) {
    return test_b(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::test_b(fuku_operand86& op, fuku_immediate86& imm8) {
    if (op.is_reg_only()) {
        return test_b(op.get_reg(), imm8);
    }
    clear_space();
    emit_b(0xF6);
    emit_operand(fuku_reg86::r_EAX, op);
    emit_b(imm8);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_TEST).set_modified_flags(D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::test_w(fuku_reg86 reg, fuku_immediate86& imm16) {
    clear_space();
    if (reg == fuku_reg86::r_EAX) {
        emit_b(0xA9);
        emit_w(imm16);
    }
    else {
        emit_b(0x66);
        emit_b(0xF7);
        emit_b(0xC0 | reg);
        emit_w(imm16);
    }
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_TEST).set_modified_flags(D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::test_w(fuku_reg86 reg, fuku_operand86& op) {
    clear_space();
    emit_b(0x66);
    emit_b(0x85);
    emit_operand(reg, op);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_TEST).set_modified_flags(D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::test_w(fuku_operand86& op, fuku_reg86 reg) { 
    return test_w(reg, op); 
}

fuku_instruction fuku_asm_x86::test_w(fuku_reg86 dst, fuku_reg86 src) { 
    return test_w(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::test_w(fuku_operand86& op, fuku_immediate86& imm16) {
    if (op.is_reg_only()) {
        return test_w(op.get_reg(), imm16);
    }
    clear_space();
    emit_b(0x66);
    emit_b(0xF7);
    emit_operand(fuku_reg86::r_EAX, op);
    emit_w(imm16);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_TEST).set_modified_flags(D_SF | D_ZF | D_PF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::xor_(fuku_reg86 dst, fuku_reg86 src) {
    return xor_(dst, fuku_operand86(src));
}

fuku_instruction fuku_asm_x86::xor_(fuku_reg86 dst, int32_t imm32) {
    clear_space();
    emit_arith(6, fuku_operand86(dst), fuku_immediate86(imm32));
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_XOR).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::xor_(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x33);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_XOR).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::xor_(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x31);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_XOR).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::xor_(fuku_operand86& dst, fuku_immediate86& x) {
    clear_space();
    emit_arith(6, dst, x);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_XOR).set_modified_flags(D_CF | D_SF | D_ZF | D_PF | D_OF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::bt(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xA3);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_BT).set_modified_flags(D_CF | D_ZF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::bts(fuku_operand86& dst, fuku_reg86 src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xAB);
    emit_operand(src, dst);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_BTS).set_modified_flags(D_CF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::bsr(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xBD);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_BSR).set_modified_flags(D_ZF).set_tested_flags(0);
}

fuku_instruction fuku_asm_x86::bsf(fuku_reg86 dst, fuku_operand86& src) {
    clear_space();
    emit_b(0x0F);
    emit_b(0xBC);
    emit_operand(dst, src);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_BSF).set_modified_flags(D_ZF).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::hlt() {
    clear_space();
    emit_b(0xF4);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_HLT).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::int3() {
    clear_space();
    emit_b(0xCC);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_INT_3).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::nop() {
    clear_space();
    emit_b(0x90);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_NOP).set_modified_flags(0).set_tested_flags(0);
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
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_RET).set_modified_flags(0).set_tested_flags(0);
}


fuku_instruction fuku_asm_x86::ud2() {
    clear_space();
    emit_b(0x0F);
    emit_b(0x0B);
    return fuku_instruction().set_op_code(bytecode, length).set_type(I_UD2).set_modified_flags(0).set_tested_flags(0);
}

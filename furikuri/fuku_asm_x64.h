#pragma once

enum fuku_asm64_size {
    asm64_size_8  = 1,
    asm64_size_16 = 2,
    asm64_size_32 = 4,
    asm64_size_64 = 8,
};

class fuku_operand64 {
    uint8_t rex = 0;
    uint8_t buf[9];
    uint8_t len = 1;
    int8_t addend;

public:   
    fuku_operand64::fuku_operand64(fuku_register base, int32_t disp);   // [base + disp/r]
    fuku_operand64::fuku_operand64(fuku_register base, fuku_register index, fuku_operand_scale scale, int32_t disp);// [base + index*scale + disp/r]  
    fuku_operand64::fuku_operand64(fuku_register index, fuku_operand_scale scale, int32_t disp);// [index*scale + disp/r]
    fuku_operand64::fuku_operand64(fuku_operand64& base, int32_t offset);
    
public:
    void fuku_operand64::set_rex(uint8_t rex);
    void fuku_operand64::set_buf(uint8_t* buf, uint8_t len);
    void fuku_operand64::set_addend(int8_t addend);
public:
    bool address_uses_reg(fuku_register reg) const;
    bool fuku_operand64::requires_rex() const;
    int  fuku_operand64::operand_size() const;
    int8_t fuku_operand64::get_addend() const;

    const uint8_t* fuku_operand64::get_buf() const;
    uint8_t fuku_operand64::get_length() const;
    uint8_t fuku_operand64::get_rex() const;
};


class fuku_asm_x64{
    uint8_t bytecode[16];
    uint8_t length;

    uint8_t displacment_offset;
    uint8_t immediate_offset;

    uint8_t short_cfg;
    
    void fuku_asm_x64::clear_space();

    void fuku_asm_x64::emit_b(uint8_t x);
    void fuku_asm_x64::emit_w(uint16_t x);
    void fuku_asm_x64::emit_dw(uint32_t x);
    void fuku_asm_x64::emit_qw(uint64_t x);

    void fuku_asm_x64::emit_immediate_b(fuku_immediate& src);
    void fuku_asm_x64::emit_immediate_w(fuku_immediate& src);
    void fuku_asm_x64::emit_immediate_dw(fuku_immediate& src);
    void fuku_asm_x64::emit_immediate_qw(fuku_immediate& src);

    void fuku_asm_x64::emit_rex_64();
    void fuku_asm_x64::emit_rex_64(fuku_register reg, fuku_register rm_reg);
    void fuku_asm_x64::emit_rex_64(fuku_register reg, fuku_operand64& op);
    void fuku_asm_x64::emit_rex_64(fuku_register rm_reg);
    void fuku_asm_x64::emit_rex_64(fuku_operand64& op);
    void fuku_asm_x64::emit_rex_32(fuku_register reg, fuku_register rm_reg);
    void fuku_asm_x64::emit_rex_32(fuku_register reg, fuku_operand64& op);
    void fuku_asm_x64::emit_rex_32(fuku_register rm_reg);
    void fuku_asm_x64::emit_rex_32(fuku_operand64& op);
    void fuku_asm_x64::emit_optional_rex_32(fuku_register reg, fuku_register rm_reg);
    void fuku_asm_x64::emit_optional_rex_32(fuku_register reg, fuku_operand64& op);
    void fuku_asm_x64::emit_optional_rex_32(fuku_register rm_reg);
    void fuku_asm_x64::emit_optional_rex_32(fuku_operand64& op);

    void fuku_asm_x64::emit_modrm(fuku_register reg, fuku_register rm_reg);
    void fuku_asm_x64::emit_modrm(int code, fuku_register rm_reg);

    void fuku_asm_x64::emit_operand(fuku_register_index reg, fuku_operand64& adr);

    void fuku_asm_x64::emit_rex(fuku_asm64_size size);
    void fuku_asm_x64::emit_rex(fuku_operand64& p1, fuku_asm64_size size);
    void fuku_asm_x64::emit_rex(fuku_register p1, fuku_asm64_size size);

    void fuku_asm_x64::emit_rex(fuku_register p1, fuku_register p2, fuku_asm64_size size);
    void fuku_asm_x64::emit_rex(fuku_register p1, fuku_operand64& p2, fuku_asm64_size size);

    void fuku_asm_x64::arithmetic_op(uint8_t opcode, fuku_register reg, fuku_operand64& op, fuku_asm64_size size);
    void fuku_asm_x64::arithmetic_op(uint8_t opcode,fuku_register reg,fuku_register rm_reg, fuku_asm64_size size);
    void fuku_asm_x64::arithmetic_op_16(uint8_t opcode, fuku_register reg, fuku_register rm_reg);
    void fuku_asm_x64::arithmetic_op_16(uint8_t opcode, fuku_register reg, fuku_operand64& rm_reg);
    void fuku_asm_x64::arithmetic_op_8(uint8_t opcode, fuku_register reg, fuku_operand64& op);
    void fuku_asm_x64::arithmetic_op_8(uint8_t opcode, fuku_register reg, fuku_register rm_reg);
    void fuku_asm_x64::immediate_arithmetic_op(uint8_t subcode,fuku_register dst,fuku_immediate& src, fuku_asm64_size size);
    void fuku_asm_x64::immediate_arithmetic_op(uint8_t subcode, fuku_operand64& dst,fuku_immediate& src, fuku_asm64_size size);
    void fuku_asm_x64::immediate_arithmetic_op_16(uint8_t subcode,fuku_register dst,fuku_immediate& src);
    void fuku_asm_x64::immediate_arithmetic_op_16(uint8_t subcode, fuku_operand64& dst,fuku_immediate& src);
    void fuku_asm_x64::immediate_arithmetic_op_8(uint8_t subcode, fuku_operand64& dst,fuku_immediate& src);
    void fuku_asm_x64::immediate_arithmetic_op_8(uint8_t subcode,fuku_register dst,fuku_immediate& src);
public:
    fuku_asm_x64::fuku_asm_x64();
    fuku_asm_x64::~fuku_asm_x64();

    fuku_instruction fuku_asm_x64::jmp(fuku_register reg);
    fuku_instruction fuku_asm_x64::jmp(fuku_operand64& adr);
    fuku_instruction fuku_asm_x64::jmp(uint32_t offset);
    fuku_instruction fuku_asm_x64::jcc(fuku_condition cond, uint32_t offset);


    fuku_instruction fuku_asm_x64::clc();
    fuku_instruction fuku_asm_x64::cld();
    fuku_instruction fuku_asm_x64::cdq();
    
    fuku_instruction fuku_asm_x64::lfence();
    fuku_instruction fuku_asm_x64::cpuid();
    fuku_instruction fuku_asm_x64::cqo();

    fuku_instruction fuku_asm_x64::hlt();
    fuku_instruction fuku_asm_x64::nop(int n);
    fuku_instruction fuku_asm_x64::ud2();
    fuku_instruction fuku_asm_x64::int3();


    fuku_instruction fuku_asm_x64::pushq(fuku_register src);
    fuku_instruction fuku_asm_x64::pushq(fuku_operand64& src);
    fuku_instruction fuku_asm_x64::pushq(fuku_immediate& value);
    fuku_instruction fuku_asm_x64::pushq_imm32(int32_t imm32);
    fuku_instruction fuku_asm_x64::pushfq();

    fuku_instruction fuku_asm_x64::popq(fuku_register dst);
    fuku_instruction fuku_asm_x64::popq(fuku_operand64& dst);
    fuku_instruction fuku_asm_x64::popfq();

    fuku_instruction fuku_asm_x64::ret(int imm16);

    fuku_instruction fuku_asm_x64::leave();
    fuku_instruction fuku_asm_x64::enter(fuku_immediate& size);

    fuku_instruction fuku_asm_x64::movb(fuku_register dst, fuku_operand64& src);
    fuku_instruction fuku_asm_x64::movb(fuku_register dst, fuku_immediate& imm);
    fuku_instruction fuku_asm_x64::movb(fuku_operand64& dst, fuku_register src);
    fuku_instruction fuku_asm_x64::movb(fuku_operand64& dst, fuku_immediate& imm);
    fuku_instruction fuku_asm_x64::movw(fuku_register dst, fuku_operand64& src);
    fuku_instruction fuku_asm_x64::movw(fuku_operand64& dst, fuku_register src);
    fuku_instruction fuku_asm_x64::movw(fuku_operand64& dst, fuku_immediate& imm);
    fuku_instruction fuku_asm_x64::mov(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::mov(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::mov(fuku_operand64& dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::mov(fuku_register dst, fuku_immediate& value, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::mov(fuku_operand64& dst, fuku_immediate& value, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::movq(fuku_register dst, int64_t value);
    fuku_instruction fuku_asm_x64::movq(fuku_register dst, uint64_t value);

    fuku_instruction fuku_asm_x64::movsxbl(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x64::movsxbl(fuku_register dst, fuku_operand64& src);
    fuku_instruction fuku_asm_x64::movsxbq(fuku_register dst, fuku_operand64& src);
    fuku_instruction fuku_asm_x64::movsxbq(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x64::movsxwl(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x64::movsxwl(fuku_register dst, fuku_operand64& src);
    fuku_instruction fuku_asm_x64::movsxwq(fuku_register dst, fuku_operand64& src);
    fuku_instruction fuku_asm_x64::movsxwq(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x64::movsxlq(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x64::movsxlq(fuku_register dst, fuku_operand64& src);

    fuku_instruction fuku_asm_x64::movzxb(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::movzxb(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::movzxw(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::movzxw(fuku_register dst, fuku_register src, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::repmovsb();
    fuku_instruction fuku_asm_x64::repmovsw();
    fuku_instruction fuku_asm_x64::repmovs(fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::lea(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::xchgb(fuku_register reg, fuku_operand64& op);
    fuku_instruction fuku_asm_x64::xchgw(fuku_register reg, fuku_operand64& op);
    fuku_instruction fuku_asm_x64::xchg(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::xchg(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::mull(fuku_register src);
    fuku_instruction fuku_asm_x64::mull(fuku_operand64& src);
    fuku_instruction fuku_asm_x64::mulq(fuku_register src);

    fuku_instruction fuku_asm_x64::imul(fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::imul(fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::imul(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::imul(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::imul(fuku_register dst, fuku_register src, fuku_immediate& imm, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::imul(fuku_register dst, fuku_operand64& src, fuku_immediate& imm, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::idiv(fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::div(fuku_register src, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::sub(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::sub(fuku_register dst, fuku_immediate& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::sub(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::sub(fuku_operand64& dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::sub(fuku_operand64& dst, fuku_immediate& src, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::decb(fuku_register dst);
    fuku_instruction fuku_asm_x64::decb(fuku_operand64& dst);
    fuku_instruction fuku_asm_x64::dec(fuku_register dst, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::dec(fuku_operand64& dst, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::add(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::add(fuku_register dst, fuku_immediate& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::add(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::add(fuku_operand64& dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::add(fuku_operand64& dst, fuku_immediate& src, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::inc(fuku_register dst, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::inc(fuku_operand64& dst, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::shld(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x64::shrd(fuku_register dst, fuku_register src);

    

    fuku_instruction fuku_asm_x64::testb(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x64::testb(fuku_register reg, fuku_immediate& mask);
    fuku_instruction fuku_asm_x64::testb(fuku_operand64& op, fuku_immediate& mask);
    fuku_instruction fuku_asm_x64::testb(fuku_operand64& op, fuku_register reg);
    fuku_instruction fuku_asm_x64::testw(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x64::testw(fuku_register reg, fuku_immediate& mask);
    fuku_instruction fuku_asm_x64::testw(fuku_operand64& op, fuku_immediate& mask);
    fuku_instruction fuku_asm_x64::testw(fuku_operand64& op, fuku_register reg);
    fuku_instruction fuku_asm_x64::test(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::test(fuku_register reg, fuku_immediate& mask, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::test(fuku_operand64& op, fuku_immediate& mask, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::test(fuku_operand64& op, fuku_register reg, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::cmpb_al(fuku_immediate& imm8);
    fuku_instruction fuku_asm_x64::cmpxchgb(fuku_operand64& dst, fuku_register src);
    fuku_instruction fuku_asm_x64::cmpxchgw(fuku_operand64& dst, fuku_register src);
    fuku_instruction fuku_asm_x64::cmpxchg(fuku_operand64& dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::cmp(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::cmp(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::cmp(fuku_operand64& dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::cmp(fuku_register dst, fuku_immediate& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::cmp(fuku_operand64& dst, fuku_immediate& src, fuku_asm64_size size);


    fuku_instruction fuku_asm_x64::and(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::and(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::and(fuku_operand64& dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::and(fuku_register dst, fuku_immediate& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::and(fuku_operand64& dst, fuku_immediate& src, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::or(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::or(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::or(fuku_operand64& dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::or(fuku_register dst, fuku_immediate& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::or(fuku_operand64& dst, fuku_immediate& src, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::xor(fuku_register dst, fuku_register src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::xor(fuku_register dst, fuku_operand64& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::xor(fuku_register dst, fuku_immediate& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::xor(fuku_operand64& dst, fuku_immediate& src, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::xor(fuku_operand64& dst, fuku_register src, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::not(fuku_register dst, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::not(fuku_operand64& dst, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::neg(fuku_register dst, fuku_asm64_size size);
    fuku_instruction fuku_asm_x64::neg(fuku_operand64& dst, fuku_asm64_size size);

    fuku_instruction fuku_asm_x64::sbb(fuku_register dst, fuku_register src, fuku_asm64_size size);
};


#pragma once

enum fuku_reg86 {
    r_EAX,
    r_ECX,
    r_EDX,
    r_EBX,
    r_ESP,
    r_EBP,
    r_ESI,
    r_EDI
};

class fuku_immediate86 {
    uint32_t imm_value;

public:
    fuku_immediate86::fuku_immediate86();
    fuku_immediate86::fuku_immediate86(uint32_t imm);
    fuku_immediate86::~fuku_immediate86();

public:
    void fuku_immediate86::set_imm(uint32_t imm);
public:
    bool fuku_immediate86::is_imm_8() const;
    bool fuku_immediate86::is_imm_16() const;
    bool fuku_immediate86::is_imm_32() const;

    uint32_t fuku_immediate86::get_imm() const;
};


class fuku_operand86 {
    uint8_t buf[6];
    uint8_t len;
    uint8_t disp_offset;

    void fuku_operand86::set_modrm(int mod, fuku_reg86 rm);
    void fuku_operand86::set_sib(operand_scale scale, fuku_reg86 index, fuku_reg86 base);
    void fuku_operand86::set_disp8(int8_t disp);
    void fuku_operand86::set_dispr(int32_t disp);
public:
    fuku_operand86::fuku_operand86(fuku_reg86 reg);
    fuku_operand86::fuku_operand86(uint32_t disp);                  // [disp/r]
    fuku_operand86::fuku_operand86(fuku_reg86 base,uint32_t disp);  // [base + disp/r]
    fuku_operand86::fuku_operand86(fuku_reg86 base, fuku_reg86 index, operand_scale scale, uint32_t disp);// [base + index*scale + disp/r]
    fuku_operand86::fuku_operand86(fuku_reg86 index, operand_scale scale, uint32_t disp);// [index*scale + disp/r]
    fuku_operand86::~fuku_operand86();

public:
    fuku_reg86 fuku_operand86::get_reg() const;
    bool fuku_operand86::is_reg_only() const;

    const uint8_t* fuku_operand86::get_buf() const;
    uint8_t fuku_operand86::get_length() const;
    uint8_t fuku_operand86::get_disp_offset() const;
};


class fuku_asm_x86{
    uint8_t bytecode[16];
    uint8_t length;
    uint8_t imm_offset;

    void fuku_asm_x86::clear_space();

    void fuku_asm_x86::emit_b(uint8_t x);
    void fuku_asm_x86::emit_w(uint16_t x);
    void fuku_asm_x86::emit_dw(uint32_t x);
    void fuku_asm_x86::emit_b(const fuku_immediate86& x);
    void fuku_asm_x86::emit_w(const fuku_immediate86& x);
    void fuku_asm_x86::emit_dw(const fuku_immediate86& x);

    void fuku_asm_x86::emit_arith(int sel, fuku_operand86& dst, const fuku_immediate86& x);
    void fuku_asm_x86::emit_operand(fuku_reg86 reg, fuku_operand86& adr);
public:
    fuku_asm_x86::fuku_asm_x86();
    fuku_asm_x86::~fuku_asm_x86();

    fuku_instruction fuku_asm_x86::jmp(fuku_reg86 reg);
    fuku_instruction fuku_asm_x86::jmp(fuku_operand86& adr);
    fuku_instruction fuku_asm_x86::jmp(uint32_t offset);
    fuku_instruction fuku_asm_x86::jcc(fuku_condition cond, uint32_t offset);

    fuku_instruction fuku_asm_x86::cpuid();

    fuku_instruction fuku_asm_x86::pushad();
    fuku_instruction fuku_asm_x86::popad();
    fuku_instruction fuku_asm_x86::pushfd();
    fuku_instruction fuku_asm_x86::popfd();
    fuku_instruction fuku_asm_x86::push( fuku_immediate86& x);
    fuku_instruction fuku_asm_x86::push_imm32(int32_t imm32);
    fuku_instruction fuku_asm_x86::push(fuku_reg86 src);
    fuku_instruction fuku_asm_x86::push(fuku_operand86& src);
    fuku_instruction fuku_asm_x86::pop(fuku_reg86 dst);
    fuku_instruction fuku_asm_x86::pop(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::enter( fuku_immediate86& size);
    fuku_instruction fuku_asm_x86::leave();

    fuku_instruction fuku_asm_x86::mov_b(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::mov_b(fuku_operand86& dst,  fuku_immediate86& src);
    fuku_instruction fuku_asm_x86::mov_b(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::mov_w(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::mov_w(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::mov_w(fuku_operand86& dst,  fuku_immediate86& src);
    fuku_instruction fuku_asm_x86::mov(fuku_reg86 dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::mov(fuku_reg86 dst,  fuku_immediate86& x);
    fuku_instruction fuku_asm_x86::mov(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::mov(fuku_reg86 dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::mov(fuku_operand86& dst,  fuku_immediate86& x);
    fuku_instruction fuku_asm_x86::mov(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::movsx_b(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::movsx_w(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::movzx_b(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::movzx_w(fuku_reg86 dst, fuku_operand86& src);

    fuku_instruction fuku_asm_x86::cld();
    fuku_instruction fuku_asm_x86::rep_movs();
    fuku_instruction fuku_asm_x86::rep_stos();
    fuku_instruction fuku_asm_x86::stos();
    fuku_instruction fuku_asm_x86::xchg(fuku_reg86 dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::xchg(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::xchg_b(fuku_reg86 reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::xchg_w(fuku_reg86 reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::lock();
    fuku_instruction fuku_asm_x86::cmpxchg(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::cmpxchg_b(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::cmpxchg_w(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::lfence();
    fuku_instruction fuku_asm_x86::pause();

    fuku_instruction fuku_asm_x86::adc(fuku_reg86 dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::adc(fuku_reg86 dst, fuku_operand86& src);

    fuku_instruction fuku_asm_x86::add(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::add(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::add(fuku_operand86& dst,  fuku_immediate86& x);

    fuku_instruction fuku_asm_x86::and_(fuku_reg86 dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::and_(fuku_reg86 dst,  fuku_immediate86& x);
    fuku_instruction fuku_asm_x86::and_(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::and_(fuku_operand86& dst,  fuku_immediate86& x);
    fuku_instruction fuku_asm_x86::and_(fuku_operand86& dst, fuku_reg86 src);

    fuku_instruction fuku_asm_x86::cmpb(fuku_operand86& op, fuku_immediate86& imm8);
    fuku_instruction fuku_asm_x86::cmpb(fuku_operand86& op, fuku_reg86 reg);
    fuku_instruction fuku_asm_x86::cmpb(fuku_reg86 reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::cmpw(fuku_operand86& op, fuku_immediate86& imm16);
    fuku_instruction fuku_asm_x86::cmpw(fuku_reg86 reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::cmpw(fuku_operand86& op, fuku_reg86 reg);
    fuku_instruction fuku_asm_x86::cmp(fuku_reg86 reg, int32_t imm32);
    fuku_instruction fuku_asm_x86::cmp(fuku_reg86 reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::cmp(fuku_operand86& op, fuku_reg86 reg);
    fuku_instruction fuku_asm_x86::cmp(fuku_operand86& op,  fuku_immediate86& imm);
    fuku_instruction fuku_asm_x86::cmpb_al(fuku_operand86& op);
    fuku_instruction fuku_asm_x86::cmpw_ax(fuku_operand86& op);

    fuku_instruction fuku_asm_x86::dec_b(fuku_reg86 dst);
    fuku_instruction fuku_asm_x86::dec_b(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::dec(fuku_reg86 dst);
    fuku_instruction fuku_asm_x86::dec(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::cdq();

    fuku_instruction fuku_asm_x86::idiv(fuku_operand86& src);
    fuku_instruction fuku_asm_x86::div(fuku_operand86& src);

    fuku_instruction fuku_asm_x86::imul(fuku_reg86 reg);
    fuku_instruction fuku_asm_x86::imul(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::imul(fuku_reg86 dst, fuku_reg86 src, int32_t imm32);
    fuku_instruction fuku_asm_x86::imul(fuku_reg86 dst, fuku_operand86& src, int32_t imm32);

    fuku_instruction fuku_asm_x86::inc(fuku_reg86 dst);
    fuku_instruction fuku_asm_x86::inc(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::lea(fuku_reg86 dst, fuku_operand86& src);

    fuku_instruction fuku_asm_x86::mul(fuku_reg86 src);

    fuku_instruction fuku_asm_x86::neg(fuku_reg86 dst);
    fuku_instruction fuku_asm_x86::neg(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::not_(fuku_reg86 dst);
    fuku_instruction fuku_asm_x86::not_(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::or_(fuku_reg86 dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::or_(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::or_(fuku_operand86& dst,  fuku_immediate86& x);
    fuku_instruction fuku_asm_x86::or_(fuku_operand86& dst, fuku_reg86 src);

    fuku_instruction fuku_asm_x86::rcl(fuku_reg86 dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::rcr(fuku_reg86 dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::ror(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::ror_cl(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::sar(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::sar_cl(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::sbb(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::shld(fuku_reg86 dst, fuku_reg86 src, uint8_t shift);
    fuku_instruction fuku_asm_x86::shld_cl(fuku_reg86 dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::shl(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::shl_cl(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::shr(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::shr_cl(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::shrd(fuku_reg86 dst, fuku_reg86 src, uint8_t shift);
    fuku_instruction fuku_asm_x86::shrd_cl(fuku_operand86& dst, fuku_reg86 src);

    fuku_instruction fuku_asm_x86::sub(fuku_operand86& dst,  fuku_immediate86& x);
    fuku_instruction fuku_asm_x86::sub(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::sub(fuku_operand86& dst, fuku_reg86 src);

    fuku_instruction fuku_asm_x86::test(fuku_reg86 reg,  fuku_immediate86& imm);
    fuku_instruction fuku_asm_x86::test(fuku_reg86 reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::test_b(fuku_reg86 reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::test(fuku_operand86& op,  fuku_immediate86& imm);
    fuku_instruction fuku_asm_x86::test_b(fuku_reg86 reg, fuku_immediate86& imm8);
    fuku_instruction fuku_asm_x86::test_b(fuku_operand86& op, fuku_immediate86& imm8);
    fuku_instruction fuku_asm_x86::test_w(fuku_reg86 reg, fuku_immediate86& imm16);
    fuku_instruction fuku_asm_x86::test_w(fuku_reg86 reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::test_w(fuku_operand86& op, fuku_immediate86& imm16);

    fuku_instruction fuku_asm_x86::xor_(fuku_reg86 dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::xor_(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::xor_(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::xor_(fuku_operand86& dst,  fuku_immediate86& x);

    fuku_instruction fuku_asm_x86::bt(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::bts(fuku_operand86& dst, fuku_reg86 src);
    fuku_instruction fuku_asm_x86::bsr(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::bsf(fuku_reg86 dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::hlt();
    fuku_instruction fuku_asm_x86::int3();
    fuku_instruction fuku_asm_x86::nop();
    fuku_instruction fuku_asm_x86::ret(int imm16);
    fuku_instruction fuku_asm_x86::ud2();


};


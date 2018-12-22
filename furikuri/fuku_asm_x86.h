#pragma once

class fuku_operand86 {
    uint8_t raw_operand[6];
    uint8_t operand_size;
    uint8_t disp_offset;

    void set_modrm(int mod, fuku_register rm);
    void set_sib(fuku_operand_scale scale, fuku_register index, fuku_register base);
    void set_disp8(int8_t disp);
    void set_dispr(int32_t disp);
public:
    fuku_operand86(fuku_register reg);
    fuku_operand86(uint32_t disp);                  // [disp/r]
    fuku_operand86(fuku_register base,uint32_t disp);  // [base + disp/r]
    fuku_operand86(fuku_register base, fuku_register index, fuku_operand_scale scale, uint32_t disp);// [base + index*scale + disp/r]
    fuku_operand86(fuku_register index, fuku_operand_scale scale, uint32_t disp);// [index*scale + disp/r]
    ~fuku_operand86();

public:
    fuku_register get_register() const;
    bool is_register_only() const;

    const uint8_t* get_buf() const;
    uint8_t get_length() const;
    uint8_t get_disp_offset() const;
};


class fuku_asm_x86 {
    uint8_t bytecode[16];
    uint8_t length;

    uint8_t displacment_offset;
    uint8_t immediate_offset;

    void fuku_asm_x86::clear_space();

    void fuku_asm_x86::emit_b(uint8_t x);
    void fuku_asm_x86::emit_w(uint16_t x);
    void fuku_asm_x86::emit_dw(uint32_t x);
    void fuku_asm_x86::emit_b(const fuku_immediate& x);
    void fuku_asm_x86::emit_w(const fuku_immediate& x);
    void fuku_asm_x86::emit_dw(const fuku_immediate& x);

    void fuku_asm_x86::emit_arith(int sel, fuku_operand86& dst, const fuku_immediate& x);
    void fuku_asm_x86::emit_operand(fuku_register reg, fuku_operand86& operand);
public:
    fuku_asm_x86::fuku_asm_x86();
    fuku_asm_x86::~fuku_asm_x86();

    //control flow
    fuku_instruction fuku_asm_x86::jmp(fuku_register reg);
    fuku_instruction fuku_asm_x86::jmp(fuku_operand86& adr);
    fuku_instruction fuku_asm_x86::jmp(uint32_t offset);
    fuku_instruction fuku_asm_x86::jcc(fuku_condition cond, uint32_t offset);

    //stack
    fuku_instruction fuku_asm_x86::pushad();
    fuku_instruction fuku_asm_x86::popad();
    fuku_instruction fuku_asm_x86::pushfd();
    fuku_instruction fuku_asm_x86::popfd();
    fuku_instruction fuku_asm_x86::push(fuku_immediate& x);
    fuku_instruction fuku_asm_x86::push_imm32(int32_t imm32);
    fuku_instruction fuku_asm_x86::push(fuku_register src);
    fuku_instruction fuku_asm_x86::push(fuku_operand86& src);
    fuku_instruction fuku_asm_x86::pop(fuku_register dst);
    fuku_instruction fuku_asm_x86::pop(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::enter(fuku_immediate& size);
    fuku_instruction fuku_asm_x86::leave();

    //movable


    fuku_instruction fuku_asm_x86::mov_b(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::mov_b(fuku_register dst, int8_t imm8);
    fuku_instruction fuku_asm_x86::mov_b(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::mov_b(fuku_operand86& dst,  fuku_immediate& src);
    fuku_instruction fuku_asm_x86::mov_b(fuku_operand86& dst, fuku_register src);
    fuku_instruction fuku_asm_x86::mov_w(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::mov_w(fuku_operand86& dst, fuku_register src);
    fuku_instruction fuku_asm_x86::mov_w(fuku_operand86& dst,  fuku_immediate& src);
    fuku_instruction fuku_asm_x86::mov(fuku_register dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::mov(fuku_register dst,  fuku_immediate& x);
    fuku_instruction fuku_asm_x86::mov(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::mov(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::mov(fuku_operand86& dst,  fuku_immediate& x);
    fuku_instruction fuku_asm_x86::mov(fuku_operand86& dst, fuku_register src);
    fuku_instruction fuku_asm_x86::movsx_b(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::movsx_w(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::movzx_b(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::movzx_w(fuku_register dst, fuku_operand86& src);

    fuku_instruction fuku_asm_x86::cld();
    fuku_instruction fuku_asm_x86::rep_movs();
    fuku_instruction fuku_asm_x86::rep_stos();
    fuku_instruction fuku_asm_x86::stos();
    fuku_instruction fuku_asm_x86::xchg(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::xchg(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::xchg_b(fuku_register reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::xchg_w(fuku_register reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::cmpxchg(fuku_operand86& dst, fuku_register src);
    fuku_instruction fuku_asm_x86::cmpxchg_b(fuku_operand86& dst, fuku_register src);
    fuku_instruction fuku_asm_x86::cmpxchg_w(fuku_operand86& dst, fuku_register src);

    fuku_instruction fuku_asm_x86::cpuid();
    fuku_instruction fuku_asm_x86::lfence();
    fuku_instruction fuku_asm_x86::pause();

    fuku_instruction fuku_asm_x86::adc(fuku_register dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::adc(fuku_register dst, fuku_operand86& src);

    fuku_instruction fuku_asm_x86::add(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::add(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::add(fuku_register dst, fuku_immediate& imm);
    fuku_instruction fuku_asm_x86::add(fuku_operand86& dst, fuku_register src);
    fuku_instruction fuku_asm_x86::add(fuku_operand86& dst,  fuku_immediate& x);
    
    fuku_instruction fuku_asm_x86::and(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::and(fuku_register dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::and(fuku_register dst,  fuku_immediate& x);
    fuku_instruction fuku_asm_x86::and(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::and(fuku_operand86& dst,  fuku_immediate& x);
    fuku_instruction fuku_asm_x86::and(fuku_operand86& dst, fuku_register src);

    fuku_instruction fuku_asm_x86::cmpb(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::cmpb(fuku_register reg, fuku_immediate& imm8);
    fuku_instruction fuku_asm_x86::cmpb(fuku_operand86& op, fuku_immediate& imm8);
    fuku_instruction fuku_asm_x86::cmpb(fuku_operand86& op, fuku_register reg);
    fuku_instruction fuku_asm_x86::cmpb(fuku_register reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::cmpw(fuku_register dst, fuku_immediate& src);
    fuku_instruction fuku_asm_x86::cmpw(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::cmpw(fuku_operand86& op, fuku_immediate& imm16);
    fuku_instruction fuku_asm_x86::cmpw(fuku_register reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::cmpw(fuku_operand86& op, fuku_register reg);
    fuku_instruction fuku_asm_x86::cmp(fuku_register reg0, fuku_register reg1);
    fuku_instruction fuku_asm_x86::cmp(fuku_register reg, fuku_immediate& imm);
    fuku_instruction fuku_asm_x86::cmp(fuku_register reg, int32_t imm32);
    fuku_instruction fuku_asm_x86::cmp(fuku_register reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::cmp(fuku_operand86& op, fuku_register reg);
    fuku_instruction fuku_asm_x86::cmp(fuku_operand86& op,  fuku_immediate& imm);
    fuku_instruction fuku_asm_x86::cmpb_al(fuku_operand86& op);
    fuku_instruction fuku_asm_x86::cmpw_ax(fuku_operand86& op);

    fuku_instruction fuku_asm_x86::dec_b(fuku_register dst);
    fuku_instruction fuku_asm_x86::dec_b(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::dec(fuku_register dst);
    fuku_instruction fuku_asm_x86::dec(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::cdq();

    fuku_instruction fuku_asm_x86::idiv(fuku_operand86& src);
    fuku_instruction fuku_asm_x86::div(fuku_operand86& src);

    fuku_instruction fuku_asm_x86::imul(fuku_register reg);
    fuku_instruction fuku_asm_x86::imul(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::imul(fuku_register dst, fuku_register src, int32_t imm32);
    fuku_instruction fuku_asm_x86::imul(fuku_register dst, fuku_operand86& src, int32_t imm32);

    fuku_instruction fuku_asm_x86::inc(fuku_register dst);
    fuku_instruction fuku_asm_x86::inc(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::lea(fuku_register dst, fuku_operand86& src);

    fuku_instruction fuku_asm_x86::mul(fuku_register src);

    fuku_instruction fuku_asm_x86::neg(fuku_register dst);
    fuku_instruction fuku_asm_x86::neg(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::not(fuku_register dst);
    fuku_instruction fuku_asm_x86::not(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::or(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::or(fuku_register dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::or(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::or(fuku_operand86& dst,  fuku_immediate& x);
    fuku_instruction fuku_asm_x86::or(fuku_operand86& dst, fuku_register src);

    fuku_instruction fuku_asm_x86::rcl(fuku_register dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::rcr(fuku_register dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::ror(fuku_register dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::ror_cl(fuku_register dst);
    fuku_instruction fuku_asm_x86::ror(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::ror_cl(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::rol(fuku_register dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::rol_cl(fuku_register dst);
    fuku_instruction fuku_asm_x86::rol(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::rol_cl(fuku_operand86& dst);

    fuku_instruction fuku_asm_x86::sar(fuku_register dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::sar_cl(fuku_register dst);
    fuku_instruction fuku_asm_x86::sar(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::sar_cl(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::sbb(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::sbb(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::shld(fuku_register dst, fuku_register src, uint8_t shift);
    fuku_instruction fuku_asm_x86::shld_cl(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::shl(fuku_register dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::shl(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::shl_cl(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::shr(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction fuku_asm_x86::shr_cl(fuku_operand86& dst);
    fuku_instruction fuku_asm_x86::shrd(fuku_register dst, fuku_register src, uint8_t shift);
    fuku_instruction fuku_asm_x86::shrd_cl(fuku_operand86& dst, fuku_register src);

    fuku_instruction fuku_asm_x86::sub(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::sub(fuku_register dst, fuku_immediate& x);
    fuku_instruction fuku_asm_x86::sub(fuku_operand86& dst,  fuku_immediate& x);
    fuku_instruction fuku_asm_x86::sub(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::sub(fuku_operand86& dst, fuku_register src);


    fuku_instruction fuku_asm_x86::test_b(fuku_register reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::test_b(fuku_register reg, fuku_immediate& imm8);
    fuku_instruction fuku_asm_x86::test_b(fuku_operand86& op, fuku_immediate& imm8);
    fuku_instruction fuku_asm_x86::test_b(fuku_register dst, fuku_register src);

    fuku_instruction fuku_asm_x86::test_w(fuku_register reg, fuku_immediate& imm16);
    fuku_instruction fuku_asm_x86::test_w(fuku_register reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::test_w(fuku_operand86& op, fuku_immediate& imm16);
    fuku_instruction fuku_asm_x86::test_w(fuku_operand86& op, fuku_register reg);
    fuku_instruction fuku_asm_x86::test_w(fuku_register dst, fuku_register src);

    fuku_instruction fuku_asm_x86::test(fuku_register reg0, fuku_register reg1);
    fuku_instruction fuku_asm_x86::test(fuku_register reg, fuku_immediate& imm);
    fuku_instruction fuku_asm_x86::test(fuku_register reg, fuku_operand86& op);
    fuku_instruction fuku_asm_x86::test(fuku_operand86& op, fuku_immediate& imm);

    fuku_instruction fuku_asm_x86::xor(fuku_register dst, fuku_register src);
    fuku_instruction fuku_asm_x86::xor(fuku_register dst, int32_t imm32);
    fuku_instruction fuku_asm_x86::xor(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::xor(fuku_operand86& dst, fuku_register src);
    fuku_instruction fuku_asm_x86::xor(fuku_operand86& dst,  fuku_immediate& x);

    fuku_instruction fuku_asm_x86::bt(fuku_operand86& dst, fuku_register src);
    fuku_instruction fuku_asm_x86::bts(fuku_operand86& dst, fuku_register src);
    fuku_instruction fuku_asm_x86::bsr(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::bsf(fuku_register dst, fuku_operand86& src);
    fuku_instruction fuku_asm_x86::hlt();
    fuku_instruction fuku_asm_x86::int3();
    fuku_instruction fuku_asm_x86::nop();
    fuku_instruction fuku_asm_x86::ret(int imm16);
    fuku_instruction fuku_asm_x86::ud2();


};


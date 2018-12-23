#pragma once

class fuku_operand86 {
    uint8_t raw_operand[6];
    uint8_t operand_size;
    uint8_t disp_offset;

    void set_modrm(uint32_t mod_size, fuku_register rm);
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
    fuku_register_index get_register() const;
    bool is_register_only() const;

    const uint8_t* get_raw_operand() const;
    uint8_t get_operand_size() const;
    uint8_t get_disp_offset() const;
};


class fuku_asm_x86 {
    uint8_t bytecode[16];
    uint8_t length;

    uint8_t displacment_offset;
    uint8_t immediate_offset;

    void clear_space();

    void emit_b(uint8_t x);
    void emit_w(uint16_t x);
    void emit_dw(uint32_t x);
    void emit_immediate_b(const fuku_immediate& imm);
    void emit_immediate_w(const fuku_immediate& imm);
    void emit_immediate_dw(const fuku_immediate& imm);

    void emit_arith(int sel, fuku_operand86& dst, const fuku_immediate& imm);
    void emit_operand(fuku_register_index reg, fuku_operand86& operand);
public:
    fuku_asm_x86();
    ~fuku_asm_x86();

    //control flow
    fuku_instruction _jmp(uint32_t offset);                      //jmp offset
    fuku_instruction _jmp(fuku_register reg);                    //jmp reg
    fuku_instruction _jmp(fuku_operand86& adr);                  //jmp [op]
    fuku_instruction _jcc(fuku_condition cond, uint32_t offset); //jcc offset
    fuku_instruction _ret(uint16_t imm16);                       //ret imm16

    //stack
    fuku_instruction _pusha();        //pusha  w  regs
    fuku_instruction _pushad();       //pushad dw regs
    fuku_instruction _popa();         //popa   w  regs
    fuku_instruction _popad();        //popad  dw regs
    fuku_instruction _pushf();        //pushf  w  flags
    fuku_instruction _pushfd();       //pushfd dw flags
    fuku_instruction _popf();         //popf   w  flags
    fuku_instruction _popfd();        //popfd  dw flags

    fuku_instruction _push(fuku_immediate& x);         //push imm (esp-4) 
    fuku_instruction _push16(fuku_immediate& x);       //push imm (esp-2)
    fuku_instruction _push(fuku_register src);         //push dwreg\wreg (esp-4)\(esp-2)
    fuku_instruction _push(fuku_operand86& src);       //push [op] (esp-4)
    fuku_instruction _push16(fuku_operand86& src);     //push [op] (esp-2)

    fuku_instruction _pop(fuku_register dst);          //pop dwreg\wreg (esp+4)\(esp+2)
    fuku_instruction _pop(fuku_operand86& dst);        //pop [op] (esp+4)
    fuku_instruction _pop16(fuku_operand86& dst);      //pop [op] (esp+2)

    fuku_instruction _enter(fuku_immediate& size, uint8_t nestinglevel); //enter size, nestinglevel
    fuku_instruction leave();                                           //leave

    //movable
    fuku_instruction _mov_b(fuku_register dst,   fuku_register src);
    fuku_instruction _mov_b(fuku_register dst,   fuku_immediate& src);
    fuku_instruction _mov_b(fuku_register dst,   fuku_operand86& src);
    fuku_instruction _mov_b(fuku_operand86& dst, fuku_immediate& src);
    fuku_instruction _mov_b(fuku_operand86& dst, fuku_register src);
    fuku_instruction _mov_w(fuku_register dst,   fuku_register src);
    fuku_instruction _mov_w(fuku_register dst,   fuku_immediate& src);
    fuku_instruction _mov_w(fuku_register dst,   fuku_operand86& src);
    fuku_instruction _mov_w(fuku_operand86& dst, fuku_register src);
    fuku_instruction _mov_w(fuku_operand86& dst, fuku_immediate& src);
    fuku_instruction _mov_dw(fuku_register dst,  fuku_immediate& src);
    fuku_instruction _mov_dw(fuku_register dst,  fuku_operand86& src);
    fuku_instruction _mov_dw(fuku_register dst,  fuku_register src);
    fuku_instruction _mov_dw(fuku_operand86& dst,fuku_immediate& src);
    fuku_instruction _mov_dw(fuku_operand86& dst,fuku_register src);

    fuku_instruction movsx_b(fuku_register dst, fuku_operand86& src);
    fuku_instruction movsx_w(fuku_register dst, fuku_operand86& src);
    fuku_instruction movzx_b(fuku_register dst, fuku_operand86& src);
    fuku_instruction movzx_w(fuku_register dst, fuku_operand86& src);

    fuku_instruction cld();
    fuku_instruction repe_movsb();
    fuku_instruction repe_stosb();
    fuku_instruction stos();
    fuku_instruction xchg(fuku_register dst, fuku_register src);
    fuku_instruction xchg(fuku_register dst, fuku_operand86& src);
    fuku_instruction xchg_b(fuku_register reg, fuku_operand86& op);
    fuku_instruction xchg_w(fuku_register reg, fuku_operand86& op);
    fuku_instruction cmpxchg(fuku_operand86& dst, fuku_register src);
    fuku_instruction cmpxchg_b(fuku_operand86& dst, fuku_register src);
    fuku_instruction cmpxchg_w(fuku_operand86& dst, fuku_register src);



    fuku_instruction adc(fuku_register dst, int32_t imm32);
    fuku_instruction adc(fuku_register dst, fuku_operand86& src);

    fuku_instruction add(fuku_register dst, fuku_register src);
    fuku_instruction add(fuku_register dst, fuku_operand86& src);
    fuku_instruction add(fuku_register dst, fuku_immediate& imm);
    fuku_instruction add(fuku_operand86& dst, fuku_register src);
    fuku_instruction add(fuku_operand86& dst,  fuku_immediate& x);
    
    fuku_instruction and(fuku_register dst, fuku_register src);
    fuku_instruction and(fuku_register dst, int32_t imm32);
    fuku_instruction and(fuku_register dst,  fuku_immediate& x);
    fuku_instruction and(fuku_register dst, fuku_operand86& src);
    fuku_instruction and(fuku_operand86& dst,  fuku_immediate& x);
    fuku_instruction and(fuku_operand86& dst, fuku_register src);

    fuku_instruction cmpb(fuku_register dst, fuku_register src);
    fuku_instruction cmpb(fuku_register reg, fuku_immediate& imm8);
    fuku_instruction cmpb(fuku_operand86& op, fuku_immediate& imm8);
    fuku_instruction cmpb(fuku_operand86& op, fuku_register reg);
    fuku_instruction cmpb(fuku_register reg, fuku_operand86& op);
    fuku_instruction cmpw(fuku_register dst, fuku_immediate& src);
    fuku_instruction cmpw(fuku_register dst, fuku_register src);
    fuku_instruction cmpw(fuku_operand86& op, fuku_immediate& imm16);
    fuku_instruction cmpw(fuku_register reg, fuku_operand86& op);
    fuku_instruction cmpw(fuku_operand86& op, fuku_register reg);
    fuku_instruction cmp(fuku_register reg0, fuku_register reg1);
    fuku_instruction cmp(fuku_register reg, fuku_immediate& imm);
    fuku_instruction cmp(fuku_register reg, int32_t imm32);
    fuku_instruction cmp(fuku_register reg, fuku_operand86& op);
    fuku_instruction cmp(fuku_operand86& op, fuku_register reg);
    fuku_instruction cmp(fuku_operand86& op,  fuku_immediate& imm);
    fuku_instruction cmpb_al(fuku_operand86& op);
    fuku_instruction cmpw_ax(fuku_operand86& op);

    fuku_instruction dec_b(fuku_register dst);
    fuku_instruction dec_b(fuku_operand86& dst);
    fuku_instruction dec(fuku_register dst);
    fuku_instruction dec(fuku_operand86& dst);

    fuku_instruction cdq();

    fuku_instruction idiv(fuku_operand86& src);
    fuku_instruction div(fuku_operand86& src);

    fuku_instruction imul(fuku_register reg);
    fuku_instruction imul(fuku_register dst, fuku_operand86& src);
    fuku_instruction imul(fuku_register dst, fuku_register src, int32_t imm32);
    fuku_instruction imul(fuku_register dst, fuku_operand86& src, int32_t imm32);

    fuku_instruction inc(fuku_register dst);
    fuku_instruction inc(fuku_operand86& dst);

    fuku_instruction lea(fuku_register dst, fuku_operand86& src);

    fuku_instruction mul(fuku_register src);

    fuku_instruction neg(fuku_register dst);
    fuku_instruction neg(fuku_operand86& dst);

    fuku_instruction not(fuku_register dst);
    fuku_instruction not(fuku_operand86& dst);

    fuku_instruction or(fuku_register dst, fuku_register src);
    fuku_instruction or(fuku_register dst, int32_t imm32);
    fuku_instruction or(fuku_register dst, fuku_operand86& src);
    fuku_instruction or(fuku_operand86& dst,  fuku_immediate& x);
    fuku_instruction or(fuku_operand86& dst, fuku_register src);

    fuku_instruction rcl(fuku_register dst, uint8_t imm8);
    fuku_instruction rcr(fuku_register dst, uint8_t imm8);
    fuku_instruction ror(fuku_register dst, uint8_t imm8);
    fuku_instruction ror_cl(fuku_register dst);
    fuku_instruction ror(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction ror_cl(fuku_operand86& dst);

    fuku_instruction rol(fuku_register dst, uint8_t imm8);
    fuku_instruction rol_cl(fuku_register dst);
    fuku_instruction rol(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction rol_cl(fuku_operand86& dst);

    fuku_instruction sar(fuku_register dst, uint8_t imm8);
    fuku_instruction sar_cl(fuku_register dst);
    fuku_instruction sar(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction sar_cl(fuku_operand86& dst);
    fuku_instruction sbb(fuku_register dst, fuku_register src);
    fuku_instruction sbb(fuku_register dst, fuku_operand86& src);
    fuku_instruction shld(fuku_register dst, fuku_register src, uint8_t shift);
    fuku_instruction shld_cl(fuku_register dst, fuku_register src);
    fuku_instruction shl(fuku_register dst, uint8_t imm8);
    fuku_instruction shl(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction shl_cl(fuku_operand86& dst);
    fuku_instruction shr(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction shr_cl(fuku_operand86& dst);
    fuku_instruction shrd(fuku_register dst, fuku_register src, uint8_t shift);
    fuku_instruction shrd_cl(fuku_operand86& dst, fuku_register src);

    fuku_instruction sub(fuku_register dst, fuku_register src);
    fuku_instruction sub(fuku_register dst, fuku_immediate& x);
    fuku_instruction sub(fuku_operand86& dst,  fuku_immediate& x);
    fuku_instruction sub(fuku_register dst, fuku_operand86& src);
    fuku_instruction sub(fuku_operand86& dst, fuku_register src);


    fuku_instruction test_b(fuku_register reg, fuku_operand86& op);
    fuku_instruction test_b(fuku_register reg, fuku_immediate& imm8);
    fuku_instruction test_b(fuku_operand86& op, fuku_immediate& imm8);
    fuku_instruction test_b(fuku_register dst, fuku_register src);

    fuku_instruction test_w(fuku_register reg, fuku_immediate& imm16);
    fuku_instruction test_w(fuku_register reg, fuku_operand86& op);
    fuku_instruction test_w(fuku_operand86& op, fuku_immediate& imm16);
    fuku_instruction test_w(fuku_operand86& op, fuku_register reg);
    fuku_instruction test_w(fuku_register dst, fuku_register src);

    fuku_instruction test(fuku_register reg0, fuku_register reg1);
    fuku_instruction test(fuku_register reg, fuku_immediate& imm);
    fuku_instruction test(fuku_register reg, fuku_operand86& op);
    fuku_instruction test(fuku_operand86& op, fuku_immediate& imm);

    fuku_instruction xor(fuku_register dst, fuku_register src);
    fuku_instruction xor(fuku_register dst, int32_t imm32);
    fuku_instruction xor(fuku_register dst, fuku_operand86& src);
    fuku_instruction xor(fuku_operand86& dst, fuku_register src);
    fuku_instruction xor(fuku_operand86& dst,  fuku_immediate& x);

    fuku_instruction bt(fuku_operand86& dst, fuku_register src);
    fuku_instruction bts(fuku_operand86& dst, fuku_register src);
    fuku_instruction bsr(fuku_register dst, fuku_operand86& src);
    fuku_instruction bsf(fuku_register dst, fuku_operand86& src);
    fuku_instruction hlt();
    fuku_instruction int3();
    fuku_instruction nop();

    fuku_instruction ud2();
    fuku_instruction cpuid();
    fuku_instruction lfence();
    fuku_instruction pause();

};


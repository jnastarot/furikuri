#pragma once

class fuku_operand86 {
    uint8_t raw_operand[6];
    uint8_t operand_size;
    uint8_t disp_offset;

    void set_modrm(uint32_t mod_size, uint32_t reg_idx);
    void set_sib(fuku_operand_scale scale, uint32_t reg_idx_index, uint32_t reg_idx_base);
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



#define genname_asm86(prefix, sname, postfix) prefix##sname##postfix

#define genrettype_asm86 fuku_instruction

#define asm_x86_def_b_r_r(name)      genrettype_asm86 genname_asm86(_,name,_b)(fuku_register dst, fuku_register src);      
#define asm_x86_def_b_r_op(name)     genrettype_asm86 genname_asm86(_,name,_b)(fuku_register dst,const fuku_operand86& src);  
#define asm_x86_def_b_r_imm(name)    genrettype_asm86 genname_asm86(_,name,_b)(fuku_register dst,const fuku_immediate& src);  
#define asm_x86_def_b_op_r(name)     genrettype_asm86 genname_asm86(_,name,_b)(const fuku_operand86& dst, fuku_register src);   
#define asm_x86_def_b_op_imm(name)   genrettype_asm86 genname_asm86(_,name,_b)(const fuku_operand86& dst,const fuku_immediate& src);  
#define asm_x86_def_w_r_r(name)      genrettype_asm86 genname_asm86(_,name,_w)(fuku_register dst, fuku_register src);      
#define asm_x86_def_w_r_op(name)     genrettype_asm86 genname_asm86(_,name,_w)(fuku_register dst,const fuku_operand86& src);     
#define asm_x86_def_w_r_imm(name)    genrettype_asm86 genname_asm86(_,name,_w)(fuku_register dst,const fuku_immediate& src);    
#define asm_x86_def_w_op_r(name)     genrettype_asm86 genname_asm86(_,name,_w)(const fuku_operand86& dst, fuku_register src);  
#define asm_x86_def_w_op_imm(name)   genrettype_asm86 genname_asm86(_,name,_w)(const fuku_operand86& dst,const fuku_immediate& src); 
#define asm_x86_def_dw_r_r(name)     genrettype_asm86 genname_asm86(_,name,_dw)(fuku_register dst, fuku_register src);      
#define asm_x86_def_dw_r_op(name)    genrettype_asm86 genname_asm86(_,name,_dw)(fuku_register dst,const fuku_operand86& src);    
#define asm_x86_def_dw_r_imm(name)   genrettype_asm86 genname_asm86(_,name,_dw)(fuku_register dst,const fuku_immediate& src);    
#define asm_x86_def_dw_op_r(name)    genrettype_asm86 genname_asm86(_,name,_dw)(const fuku_operand86& dst, fuku_register src);  
#define asm_x86_def_dw_op_imm(name)  genrettype_asm86 genname_asm86(_,name,_dw)(const fuku_operand86& dst,const fuku_immediate& src);    

#define asm_x86_def_b_r(name)     genrettype_asm86 genname_asm86(_,name,_b)(fuku_register src);
#define asm_x86_def_b_op(name)    genrettype_asm86 genname_asm86(_,name,_b)(const fuku_operand86& src);
#define asm_x86_def_b_imm(name)   genrettype_asm86 genname_asm86(_,name,_b)(const fuku_immediate& src);
#define asm_x86_def_w_r(name)     genrettype_asm86 genname_asm86(_,name,_w)(fuku_register src);
#define asm_x86_def_w_op(name)    genrettype_asm86 genname_asm86(_,name,_w)(const fuku_operand86& src);
#define asm_x86_def_w_imm(name)   genrettype_asm86 genname_asm86(_,name,_w)(const fuku_immediate& src);
#define asm_x86_def_dw_r(name)    genrettype_asm86 genname_asm86(_,name,_dw)(fuku_register src);
#define asm_x86_def_dw_op(name)   genrettype_asm86 genname_asm86(_,name,_dw)(const fuku_operand86& src);
#define asm_x86_def_dw_imm(name)  genrettype_asm86 genname_asm86(_,name,_dw)(const fuku_immediate& src);


#define asm_x86_def_noarg(name) genrettype_asm86 name();

#define asm_x86_def_full(name)  \
    asm_x86_def_b_r_r(name)      \
    asm_x86_def_b_r_imm(name)    \
    asm_x86_def_b_r_op(name)     \
    asm_x86_def_b_op_imm(name)   \
    asm_x86_def_b_op_r(name)     \
    asm_x86_def_w_r_r(name)      \
    asm_x86_def_w_r_imm(name)    \
    asm_x86_def_w_r_op(name)     \
    asm_x86_def_w_op_imm(name)   \
    asm_x86_def_w_op_r(name)     \
    asm_x86_def_dw_r_r(name)      \
    asm_x86_def_dw_r_imm(name)    \
    asm_x86_def_dw_r_op(name)     \
    asm_x86_def_dw_op_imm(name)   \
    asm_x86_def_dw_op_r(name)     \

#define asm_x86_def_r_op_one_op(name) \
    asm_x86_def_b_r(name)\
    asm_x86_def_b_op(name)\
    asm_x86_def_w_r(name)\
    asm_x86_def_w_op(name)\
    asm_x86_def_dw_r(name)\
    asm_x86_def_dw_op(name)\

#define asm_x86_def_wdw_one_op(name) \
    asm_x86_def_w_r(name)\
    asm_x86_def_w_op(name)\
    asm_x86_def_w_imm(name)\
    asm_x86_def_dw_r(name)\
    asm_x86_def_dw_op(name)\
    asm_x86_def_dw_imm(name)\

#define asm_x86_def_eip_one_op(name) \
    genrettype_asm86 name(fuku_register src);\
    genrettype_asm86 name(const fuku_operand86& src);\
    genrettype_asm86 name(const fuku_immediate& src);\

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

    void emit_arith(int sel, const fuku_operand86& dst, const fuku_immediate& imm);
    void emit_operand(fuku_register_index reg, const fuku_operand86& operand);
public:
    fuku_asm_x86();
    ~fuku_asm_x86();

    //control flow
    asm_x86_def_eip_one_op(_jmp)
    asm_x86_def_eip_one_op(_call)

    fuku_instruction _jcc(fuku_condition cond, uint32_t offset); //jcc offset
    asm_x86_def_noarg(_ret)
    fuku_instruction _ret(uint16_t imm16);                       //ret imm16

    //stack
    asm_x86_def_noarg(_pusha)       //pusha  w  regs
    asm_x86_def_noarg(_pushad)      //pushad dw regs
    asm_x86_def_noarg(_popa)        //popa   w  regs
    asm_x86_def_noarg(_popad)       //popad  dw regs
    asm_x86_def_noarg(_pushf)       //pushf  w  flags
    asm_x86_def_noarg(_pushfd)      //pushfd dw flags
    asm_x86_def_noarg(_popf)        //popf   w  flags
    asm_x86_def_noarg(_popfd)       //popfd  dw flags

    asm_x86_def_wdw_one_op(push)
    asm_x86_def_wdw_one_op(pop)

    fuku_instruction _enter(const fuku_immediate& size, uint8_t nestinglevel); //enter size, nestinglevel

    asm_x86_def_noarg(leave_)

//movable
    asm_x86_def_full(mov)

    fuku_instruction _movsx_b(fuku_register dst, fuku_operand86& src);   //movsx (eax\ax), byte ptr[op]
    fuku_instruction _movsx_b(fuku_register dst, fuku_register src);     //movsx (eax\ax), al
    fuku_instruction _movsx_w(fuku_register dst, fuku_operand86& src);   //movsx eax, word ptr[op]
    fuku_instruction _movsx_w(fuku_register dst, fuku_register src);     //movsx eax, ax

    fuku_instruction _movzx_b(fuku_register dst, fuku_operand86& src);   //movzx (eax\ax), byte ptr[op]
    fuku_instruction _movzx_b(fuku_register dst, fuku_register src);     //movzx (eax\ax), al
    fuku_instruction _movzx_w(fuku_register dst, fuku_operand86& src);   //movzx eax, word ptr[op]
    fuku_instruction _movzx_w(fuku_register dst, fuku_register src);     //movzx eax, ax

    asm_x86_def_b_r_r(xchg)
    asm_x86_def_b_r_op(xchg)
    asm_x86_def_w_r_r(xchg)
    asm_x86_def_w_r_op(xchg)
    asm_x86_def_dw_r_r(xchg)
    asm_x86_def_dw_r_op(xchg)

    asm_x86_def_w_r_op(lea)
    asm_x86_def_dw_r_op(lea)

//math
    asm_x86_def_full(add)
    asm_x86_def_full(or)
    asm_x86_def_full(adc)
    asm_x86_def_full(sbb)
    asm_x86_def_full(and)
    asm_x86_def_full(sub)
    asm_x86_def_full(xor)
    asm_x86_def_full(cmp)

    asm_x86_def_r_op_one_op(not)
    asm_x86_def_r_op_one_op(neg)
    asm_x86_def_r_op_one_op(mul)
    asm_x86_def_r_op_one_op(imul)
    asm_x86_def_r_op_one_op(div)
    asm_x86_def_r_op_one_op(idiv)

    asm_x86_def_r_op_one_op(inc)
    asm_x86_def_r_op_one_op(dec)

    asm_x86_def_noarg(_movsb)
    asm_x86_def_noarg(_movsw)
    asm_x86_def_noarg(_movsd)
    asm_x86_def_noarg(_stosb)
    asm_x86_def_noarg(_stosw)
    asm_x86_def_noarg(_stosd)

    asm_x86_def_noarg(_nop)
    asm_x86_def_noarg(_int3)
    asm_x86_def_noarg(_hlt)
    asm_x86_def_noarg(_cld)
    asm_x86_def_noarg(_cdq)
    asm_x86_def_noarg(_ud2)
    asm_x86_def_noarg(_cpuid)
    asm_x86_def_noarg(_pause)
    asm_x86_def_noarg(_rdtsc)
    asm_x86_def_noarg(_lfence)

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

    fuku_instruction rcl(fuku_register dst, uint8_t imm8);
    fuku_instruction rcr(fuku_register dst, uint8_t imm8);
    fuku_instruction ror(fuku_register dst, uint8_t imm8);
    fuku_instruction ror(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction ror_cl(fuku_register dst);
    fuku_instruction ror_cl(fuku_operand86& dst);

    fuku_instruction rol(fuku_register dst, uint8_t imm8);
    fuku_instruction rol(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction rol_cl(fuku_register dst);
    fuku_instruction rol_cl(fuku_operand86& dst);

    fuku_instruction sar(fuku_register dst, uint8_t imm8);
    fuku_instruction sar_cl(fuku_register dst);
    fuku_instruction sar(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction sar_cl(fuku_operand86& dst);

    fuku_instruction shld(fuku_register dst, fuku_register src, uint8_t shift);
    fuku_instruction shld_cl(fuku_register dst, fuku_register src);
    fuku_instruction shrd(fuku_register dst, fuku_register src, uint8_t shift);
    fuku_instruction shrd_cl(fuku_operand86& dst, fuku_register src);

    fuku_instruction shl(fuku_register dst, uint8_t imm8);
    fuku_instruction shl(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction shl_cl(fuku_operand86& dst);
    fuku_instruction shr(fuku_operand86& dst, uint8_t imm8);
    fuku_instruction shr_cl(fuku_operand86& dst);


    fuku_instruction cmpxchg(fuku_operand86& dst, fuku_register src);
    fuku_instruction cmpxchg_b(fuku_operand86& dst, fuku_register src);
    fuku_instruction cmpxchg_w(fuku_operand86& dst, fuku_register src);


    fuku_instruction bt(fuku_operand86& dst, fuku_register src);
    fuku_instruction bts(fuku_operand86& dst, fuku_register src);
    fuku_instruction bsr(fuku_register dst, fuku_operand86& src);
    fuku_instruction bsf(fuku_register dst, fuku_operand86& src);
};


#undef genname_asm86
#undef asm_x86_def_math
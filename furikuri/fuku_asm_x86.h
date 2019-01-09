#pragma once


#define asm_def_full(name)  \
    asm_def_b_r_r(name)      \
    asm_def_b_r_imm(name)    \
    asm_def_b_r_op(name)     \
    asm_def_b_op_imm(name)   \
    asm_def_b_op_r(name)     \
    asm_def_w_r_r(name)      \
    asm_def_w_r_imm(name)    \
    asm_def_w_r_op(name)     \
    asm_def_w_op_imm(name)   \
    asm_def_w_op_r(name)     \
    asm_def_dw_r_r(name)      \
    asm_def_dw_r_imm(name)    \
    asm_def_dw_r_op(name)     \
    asm_def_dw_op_imm(name)   \
    asm_def_dw_op_r(name)     \

#define asm_def_full_shift(name)\
    asm_def_b_r(name##_cl)  \
    asm_def_b_op(name##_cl) \
    asm_def_b_r_imm(name)  \
    asm_def_b_op_imm(name) \
    asm_def_w_r(name##_cl)  \
    asm_def_w_op(name##_cl) \
    asm_def_w_r_imm(name)  \
    asm_def_w_op_imm(name) \
    asm_def_dw_r(name##_cl) \
    asm_def_dw_op(name##_cl)\
    asm_def_dw_r_imm(name) \
    asm_def_dw_op_imm(name)\

#define asm_def_r_op_one_op(name) \
    asm_def_b_r(name)\
    asm_def_b_op(name)\
    asm_def_w_r(name)\
    asm_def_w_op(name)\
    asm_def_dw_r(name)\
    asm_def_dw_op(name)\

#define asm_def_wdw_one_op(name) \
    asm_def_w_r(name)\
    asm_def_w_op(name)\
    asm_def_w_imm(name)\
    asm_def_dw_r(name)\
    asm_def_dw_op(name)\
    asm_def_dw_imm(name)\

#define gen_func_body_bittest(name) \
    asm_def_w_r_r(name)      \
    asm_def_w_r_imm(name)    \
    asm_def_w_op_r(name)     \
    asm_def_w_op_imm(name)   \
    asm_def_dw_r_r(name)      \
    asm_def_dw_r_imm(name)    \
    asm_def_dw_op_r(name)     \
    asm_def_dw_op_imm(name)   \
   

#define asm_def_eip_one_op(name) \
    genrettype_asm name(fuku_register src);\
    genrettype_asm name(const fuku_operand& src);\
    genrettype_asm name(const fuku_immediate& src);\


class fuku_asm_x86 {
    uint8_t bytecode[16];
    uint8_t length;

    uint8_t displacment_offset;
    uint8_t immediate_offset;

    uint8_t short_cfg;

    void clear_space();

    void emit_b(uint8_t x);
    void emit_w(uint16_t x);
    void emit_dw(uint32_t x);
    void emit_immediate_b(const fuku_immediate& imm);
    void emit_immediate_w(const fuku_immediate& imm);
    void emit_immediate_dw(const fuku_immediate& imm);

    void emit_modrm(fuku_register reg, fuku_register rm_reg);
    void emit_modrm(int code, fuku_register rm_reg);

    void emit_operand(fuku_register_index reg, const fuku_operand& operand);
public:
    fuku_asm_x86();
    ~fuku_asm_x86();

    uint8_t get_displacment_offset();
    uint8_t get_immediate_offset();

    bool is_used_short_eax();
    bool is_used_short_disp();
    bool is_used_short_imm();
public:

//control flow
    asm_def_eip_one_op(_jmp)
    asm_def_eip_one_op(_call)
    genrettype_asm _jcc(fuku_condition cond, const fuku_immediate& imm);
    asm_def_noarg(_ret)
    genrettype_asm _ret(const fuku_immediate& imm);

//stack
    asm_def_noarg(_pusha)       //pusha  w  regs
    asm_def_noarg(_pushad)      //pushad dw regs
    asm_def_noarg(_popa)        //popa   w  regs
    asm_def_noarg(_popad)       //popad  dw regs
    asm_def_noarg(_pushf)       //pushf  w  flags
    asm_def_noarg(_pushfd)      //pushfd dw flags
    asm_def_noarg(_popf)        //popf   w  flags
    asm_def_noarg(_popfd)       //popfd  dw flags

    asm_def_wdw_one_op(push)
    asm_def_wdw_one_op(pop)

    genrettype_asm _enter(const fuku_immediate& size, uint8_t nestinglevel); //enter size, nestinglevel

    asm_def_noarg(leave_)

//movable
    asm_def_full(mov)

    asm_def_b_r_op(movsx)  //movsx (eax\ax), byte ptr[op]
    asm_def_b_r_r(movsx)   //movsx (eax\ax), al   
    asm_def_w_r_op(movsx)  //movsx eax, word ptr[op]
    asm_def_w_r_r(movsx)   //movsx eax, ax   

    asm_def_b_r_op(movzx)  //movzx (eax\ax), byte ptr[op]
    asm_def_b_r_r(movzx)   //movzx (eax\ax), al   
    asm_def_w_r_op(movzx)  //movzx eax, word ptr[op]
    asm_def_w_r_r(movzx)   //movzx eax, ax   

    asm_def_b_r_r(xchg)
    asm_def_b_r_op(xchg)
    asm_def_w_r_r(xchg)
    asm_def_w_r_op(xchg)
    asm_def_dw_r_r(xchg)
    asm_def_dw_r_op(xchg)

    asm_def_w_r_op(lea)
    asm_def_dw_r_op(lea)

    asm_def_noarg(_movsb)
    asm_def_noarg(_movsw)
    asm_def_noarg(_movsd)
    asm_def_noarg(_stosb)
    asm_def_noarg(_stosw)
    asm_def_noarg(_stosd)

//math
    asm_def_full(add)
    asm_def_full(or)
    asm_def_full(adc)
    asm_def_full(sbb)
    asm_def_full(and)
    asm_def_full(sub)
    asm_def_full(xor)
    asm_def_full(cmp)

    asm_def_r_op_one_op(not)
    asm_def_r_op_one_op(neg)
    asm_def_r_op_one_op(mul)
    asm_def_r_op_one_op(imul)
    asm_def_r_op_one_op(div)
    asm_def_r_op_one_op(idiv)

    asm_def_r_op_one_op(inc)
    asm_def_r_op_one_op(dec)

    asm_def_b_r_r(test)
    asm_def_b_r_imm(test)
    asm_def_b_op_r(test)
    asm_def_b_op_imm(test)
    asm_def_w_r_r(test)
    asm_def_w_r_imm(test)
    asm_def_w_op_r(test)
    asm_def_w_op_imm(test)
    asm_def_dw_r_r(test)
    asm_def_dw_r_imm(test)
    asm_def_dw_op_r(test)
    asm_def_dw_op_imm(test)
 

//shift
    asm_def_full_shift(rol)
    asm_def_full_shift(ror)
    asm_def_full_shift(rcl)
    asm_def_full_shift(rcr)
    asm_def_full_shift(shl)
    asm_def_full_shift(shr)
    asm_def_full_shift(sar)

//bittest
    gen_func_body_bittest(bt)
    gen_func_body_bittest(bts)
    gen_func_body_bittest(btr)
    gen_func_body_bittest(btc)

//misc
    asm_def_noarg(_nop)
    asm_def_noarg(_int3)
    asm_def_noarg(_hlt)
    asm_def_noarg(_cld)
    asm_def_noarg(_cdq)
    asm_def_noarg(_ud2)
    asm_def_noarg(_cpuid)
    asm_def_noarg(_pause)
    asm_def_noarg(_rdtsc)
    asm_def_noarg(_lfence)
};

#undef asm_def_full
#undef asm_def_full_shift
#undef asm_def_r_op_one_op
#undef asm_def_wdw_one_op
#undef gen_func_body_bittest
#undef asm_def_eip_one_op
#pragma once

#define genname_asm86(prefix, sname, postfix) prefix##sname##postfix

#define genrettype_asm86 fuku_instruction

#define asm_x86_def_b_r_r(name)      genrettype_asm86 genname_asm86(_,name,_b)(fuku_register dst, fuku_register src);      
#define asm_x86_def_b_r_op(name)     genrettype_asm86 genname_asm86(_,name,_b)(fuku_register dst,const fuku_operand& src);  
#define asm_x86_def_b_r_imm(name)    genrettype_asm86 genname_asm86(_,name,_b)(fuku_register dst,const fuku_immediate& src);  
#define asm_x86_def_b_op_r(name)     genrettype_asm86 genname_asm86(_,name,_b)(const fuku_operand& dst, fuku_register src);   
#define asm_x86_def_b_op_imm(name)   genrettype_asm86 genname_asm86(_,name,_b)(const fuku_operand& dst,const fuku_immediate& src);  
#define asm_x86_def_w_r_r(name)      genrettype_asm86 genname_asm86(_,name,_w)(fuku_register dst, fuku_register src);      
#define asm_x86_def_w_r_op(name)     genrettype_asm86 genname_asm86(_,name,_w)(fuku_register dst,const fuku_operand& src);     
#define asm_x86_def_w_r_imm(name)    genrettype_asm86 genname_asm86(_,name,_w)(fuku_register dst,const fuku_immediate& src);    
#define asm_x86_def_w_op_r(name)     genrettype_asm86 genname_asm86(_,name,_w)(const fuku_operand& dst, fuku_register src);  
#define asm_x86_def_w_op_imm(name)   genrettype_asm86 genname_asm86(_,name,_w)(const fuku_operand& dst,const fuku_immediate& src); 
#define asm_x86_def_dw_r_r(name)     genrettype_asm86 genname_asm86(_,name,_dw)(fuku_register dst, fuku_register src);      
#define asm_x86_def_dw_r_op(name)    genrettype_asm86 genname_asm86(_,name,_dw)(fuku_register dst,const fuku_operand& src);    
#define asm_x86_def_dw_r_imm(name)   genrettype_asm86 genname_asm86(_,name,_dw)(fuku_register dst,const fuku_immediate& src);    
#define asm_x86_def_dw_op_r(name)    genrettype_asm86 genname_asm86(_,name,_dw)(const fuku_operand& dst, fuku_register src);  
#define asm_x86_def_dw_op_imm(name)  genrettype_asm86 genname_asm86(_,name,_dw)(const fuku_operand& dst,const fuku_immediate& src);    

#define asm_x86_def_b_r(name)     genrettype_asm86 genname_asm86(_,name,_b)(fuku_register src);
#define asm_x86_def_b_op(name)    genrettype_asm86 genname_asm86(_,name,_b)(const fuku_operand& src);
#define asm_x86_def_b_imm(name)   genrettype_asm86 genname_asm86(_,name,_b)(const fuku_immediate& src);
#define asm_x86_def_w_r(name)     genrettype_asm86 genname_asm86(_,name,_w)(fuku_register src);
#define asm_x86_def_w_op(name)    genrettype_asm86 genname_asm86(_,name,_w)(const fuku_operand& src);
#define asm_x86_def_w_imm(name)   genrettype_asm86 genname_asm86(_,name,_w)(const fuku_immediate& src);
#define asm_x86_def_dw_r(name)    genrettype_asm86 genname_asm86(_,name,_dw)(fuku_register src);
#define asm_x86_def_dw_op(name)   genrettype_asm86 genname_asm86(_,name,_dw)(const fuku_operand& src);
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

#define asm_x86_def_full_shift(name)\
    asm_x86_def_b_r(name##_cl)  \
    asm_x86_def_b_op(name##_cl) \
    asm_x86_def_b_r_imm(name)  \
    asm_x86_def_b_op_imm(name) \
    asm_x86_def_w_r(name##_cl)  \
    asm_x86_def_w_op(name##_cl) \
    asm_x86_def_w_r_imm(name)  \
    asm_x86_def_w_op_imm(name) \
    asm_x86_def_dw_r(name##_cl) \
    asm_x86_def_dw_op(name##_cl)\
    asm_x86_def_dw_r_imm(name) \
    asm_x86_def_dw_op_imm(name)\

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

#define gen_func_body_bittest(name) \
    asm_x86_def_w_r_r(name)      \
    asm_x86_def_w_r_imm(name)    \
    asm_x86_def_w_op_r(name)     \
    asm_x86_def_w_op_imm(name)   \
    asm_x86_def_dw_r_r(name)      \
    asm_x86_def_dw_r_imm(name)    \
    asm_x86_def_dw_op_r(name)     \
    asm_x86_def_dw_op_imm(name)   \
   

#define asm_x86_def_eip_one_op(name) \
    genrettype_asm86 name(fuku_register src);\
    genrettype_asm86 name(const fuku_operand& src);\
    genrettype_asm86 name(const fuku_immediate& src);\

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
    asm_x86_def_eip_one_op(_jmp)
    asm_x86_def_eip_one_op(_call)
    genrettype_asm86 _jcc(fuku_condition cond, const fuku_immediate& imm);
    asm_x86_def_noarg(_ret)
    genrettype_asm86 _ret(const fuku_immediate& imm);

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

    genrettype_asm86 _enter(const fuku_immediate& size, uint8_t nestinglevel); //enter size, nestinglevel

    asm_x86_def_noarg(leave_)

//movable
    asm_x86_def_full(mov)

    asm_x86_def_b_r_op(movsx)  //movsx (eax\ax), byte ptr[op]
    asm_x86_def_b_r_r(movsx)   //movsx (eax\ax), al   
    asm_x86_def_w_r_op(movsx)  //movsx eax, word ptr[op]
    asm_x86_def_w_r_r(movsx)   //movsx eax, ax   

    asm_x86_def_b_r_op(movzx)  //movzx (eax\ax), byte ptr[op]
    asm_x86_def_b_r_r(movzx)   //movzx (eax\ax), al   
    asm_x86_def_w_r_op(movzx)  //movzx eax, word ptr[op]
    asm_x86_def_w_r_r(movzx)   //movzx eax, ax   

    asm_x86_def_b_r_r(xchg)
    asm_x86_def_b_r_op(xchg)
    asm_x86_def_w_r_r(xchg)
    asm_x86_def_w_r_op(xchg)
    asm_x86_def_dw_r_r(xchg)
    asm_x86_def_dw_r_op(xchg)

    asm_x86_def_w_r_op(lea)
    asm_x86_def_dw_r_op(lea)

    asm_x86_def_noarg(_movsb)
    asm_x86_def_noarg(_movsw)
    asm_x86_def_noarg(_movsd)
    asm_x86_def_noarg(_stosb)
    asm_x86_def_noarg(_stosw)
    asm_x86_def_noarg(_stosd)

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

    asm_x86_def_b_r_r(test)
    asm_x86_def_b_r_imm(test)
    asm_x86_def_b_op_r(test)
    asm_x86_def_b_op_imm(test)
    asm_x86_def_w_r_r(test)
    asm_x86_def_w_r_imm(test)
    asm_x86_def_w_op_r(test)
    asm_x86_def_w_op_imm(test)
    asm_x86_def_dw_r_r(test)
    asm_x86_def_dw_r_imm(test)
    asm_x86_def_dw_op_r(test)
    asm_x86_def_dw_op_imm(test)
 

//shift
    asm_x86_def_full_shift(rol)
    asm_x86_def_full_shift(ror)
    asm_x86_def_full_shift(rcl)
    asm_x86_def_full_shift(rcr)
    asm_x86_def_full_shift(shl)
    asm_x86_def_full_shift(shr)
    asm_x86_def_full_shift(sar)

//bittest
    gen_func_body_bittest(bt)
    gen_func_body_bittest(bts)
    gen_func_body_bittest(btr)
    gen_func_body_bittest(btc)

//misc
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
};
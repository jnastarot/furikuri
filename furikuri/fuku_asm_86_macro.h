#pragma once

/*
    good references
        https://www.felixcloutier.com/x86
        https://c9x.me/x86/
*/

#define asm86_arith_add 0
#define asm86_arith_or  1
#define asm86_arith_adc 2
#define asm86_arith_sbb 3
#define asm86_arith_and 4
#define asm86_arith_sub 5
#define asm86_arith_xor 6
#define asm86_arith_cmp 7

#define asm86_arith_ex_not  2
#define asm86_arith_ex_neg  3
#define asm86_arith_ex_mul  4
#define asm86_arith_ex_imul 5
#define asm86_arith_ex_div  6
#define asm86_arith_ex_idiv 7

#define asm86_arith_inc 0
#define asm86_arith_dec 1

#define asm86_shift_rol 0
#define asm86_shift_ror 1
#define asm86_shift_rcl 2
#define asm86_shift_rcr 3
#define asm86_shift_shl 4
#define asm86_shift_shr 5
#define asm86_shift_sar 7


#define genname_asm86(prefix, sname, postfix) prefix ## sname ## postfix

#define genrettype_asm86 fuku_instruction

#define gencleanerdata \
     clear_space();

#define gen_func_return(cap_id, cap_eflags)\
     return fuku_instruction().set_op_code(bytecode, length) \
        .set_id(cap_id) \
        .set_eflags(cap_eflags);  \

#define gen_func_body_onebyte_no_arg(name ,byte, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: ##name## () { \
        gencleanerdata\
        emit_b(byte);\
        gen_func_return(cap_id, cap_eflags)\
    } 

#define gen_func_body_twobyte_no_arg(name ,byte1,byte2, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: ##name## () { \
        gencleanerdata\
        emit_b(byte1);\
        emit_b(byte2);\
        gen_func_return(cap_id, cap_eflags)\
    } 

#define gen_func_body_threebyte_no_arg(name ,byte1,byte2,byte3, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: ##name## () { \
        gencleanerdata\
        emit_b(byte1);\
        emit_b(byte2);\
        emit_b(byte3);\
        gen_func_return(cap_id, cap_eflags)\
    } 




#define gen_func_body_ff_r(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: ##name## (fuku_register src) { \
        gencleanerdata\
        emit_b(0xFF);\
        emit_b(0xC0 + 8*type + fuku_get_index_reg(src));\
        gen_func_return(cap_id, cap_eflags)\
    } 

#define gen_func_body_ff_offset(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: ##name## (const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(type);\
        emit_immediate_dw(src);\
        gen_func_return(cap_id, cap_eflags)\
    } 

#define gen_func_body_ff_op(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: ##name## (const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(0xFF);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } 


#define gen_func_body_arith(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register dst, fuku_register src) { \
        gencleanerdata\
        emit_b(8*type);\
        emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(0x80);\
        emit_b((0xC0 | fuku_get_index_reg(dst)) + 8*type);\
        emit_immediate_b(src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register dst,const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(0x02 + 8*type);\
        emit_operand(fuku_get_index_reg(dst), src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (const fuku_operand86& dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(0x80);\
        emit_operand((fuku_register_index)type, dst);\
        emit_immediate_b(src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (const fuku_operand86& dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x00 + 8*type);\
        emit_operand(fuku_get_index_reg(src), dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register dst, fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x01 + 8*type);\
        emit_b(0xC0 | fuku_get_index_reg(src) << 3 | fuku_get_index_reg(dst));\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        if (src.is_8()) {\
            emit_b(0x83);\
            emit_b( (0xC0 | fuku_get_index_reg(dst)) + 8*type);\
            emit_immediate_b(src);\
        }else{\
            emit_b(0x81);\
            emit_b( (0xC0 | fuku_get_index_reg(dst)) + 8*type);\
            emit_immediate_w(src);\
        }\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register dst,const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x03 + 8*type);\
        emit_operand(fuku_get_index_reg(dst), src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand86& dst, fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x01 + 8*type);\
        emit_operand(fuku_get_index_reg(src), dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand86& dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        if (src.is_8()) {\
            emit_b(0x83);\
            emit_operand((fuku_register_index)type, dst);\
            emit_immediate_w(src);\
        }else{\
            emit_b(0x81);\
            emit_operand((fuku_register_index)type, dst);\
            emit_immediate_w(src);\
        }\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x01 + 8*type);\
        emit_operand(fuku_get_index_reg(src), dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register dst,const fuku_immediate& src) { \
        gencleanerdata\
         if (src.is_8()) {\
            emit_b(0x83);\
            emit_b( (0xC0 | fuku_get_index_reg(dst)) + 8*type);\
            emit_immediate_b(src);\
        }else{\
            emit_b(0x81);\
            emit_b( (0xC0 | fuku_get_index_reg(dst)) + 8*type);\
            emit_immediate_w(src);\
        }\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register dst,const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(0x03 + 8*type);\
        emit_operand(fuku_get_index_reg(dst), src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand86& dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x01 + 8*type);\
        emit_operand(fuku_get_index_reg(src), dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand86& dst,const fuku_immediate& src) { \
        gencleanerdata\
         if (src.is_8()) {\
            emit_b(0x83);\
            emit_operand((fuku_register_index)type, dst);\
            emit_immediate_w(src);\
        }else{\
            emit_b(0x81);\
            emit_operand((fuku_register_index)type, dst);\
            emit_immediate_w(src);\
        }\
        gen_func_return(cap_id, cap_eflags)\
    } 
    
#define gen_func_body_arith_ex_one_op(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register src) { \
        gencleanerdata\
        emit_b(0xF6);\
        emit_b(0xC0 + 8*type + fuku_get_index_reg(src));\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(0xF6);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0xF7);\
        emit_b(0xC0 + 8*type + fuku_get_index_reg(src));\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0xF7);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register src) { \
        gencleanerdata\
        emit_b(0xF7);\
        emit_b(0xC0 + 8*type + fuku_get_index_reg(src));\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(0xF7);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } 

#define gen_func_body_arith_incdec(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register src) { \
        gencleanerdata\
        emit_b(0xFE);\
        emit_b(0xC0 + 8*type + fuku_get_index_reg(src));\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(0xFE);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0xFF);\
        emit_b(0xC0 + 8*type + fuku_get_index_reg(src));\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0xFF);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register src) { \
        gencleanerdata\
        emit_b(0xFF);\
        emit_b(0xC0 + 8*type + fuku_get_index_reg(src));\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand86& src) { \
        gencleanerdata\
        emit_b(0xFF);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } 

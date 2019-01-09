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

#define asm86_bittest_bt  4
#define asm86_bittest_bts 5
#define asm86_bittest_btr 6
#define asm86_bittest_btc 7


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
        emit_modrm(type, src);\
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
    genrettype_asm86 fuku_asm_x86:: ##name## (const fuku_operand& src) { \
        gencleanerdata\
        emit_b(0xFF);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } 


#define gen_func_body_arith(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register dst, fuku_register src) { \
        gencleanerdata\
        emit_b(8*type);\
        emit_modrm(src, dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register dst,const fuku_immediate& src) { \
        gencleanerdata\
        if(is_used_short_eax() && dst == fuku_register::FUKU_REG_AL) {\
            emit_b(0x04 + 8*type); \
        } else {\
            emit_b(0x80); \
            emit_modrm(type, dst);\
        }\
        emit_immediate_b(src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register dst,const fuku_operand& src) { \
        gencleanerdata\
        emit_b(0x02 + 8*type);\
        emit_operand(fuku_get_index_by_register(dst), src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (const fuku_operand& dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(0x80);\
        emit_operand((fuku_register_index)type, dst);\
        emit_immediate_b(src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (const fuku_operand& dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x00 + 8*type);\
        emit_operand(fuku_get_index_by_register(src), dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
\
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register dst, fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x01 + 8*type);\
        emit_modrm(src, dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        if(is_used_short_eax() && dst == fuku_register::FUKU_REG_AX) {\
            emit_b(0x05 + 8*type); \
            emit_immediate_w(src);\
        } else {\
            if (is_used_short_imm() && src.is_8()) {\
                emit_b(0x83);\
                emit_modrm(type, dst);\
                emit_immediate_b(src);\
            }else{\
                emit_b(0x81);\
                emit_modrm(type, dst);\
                emit_immediate_w(src);\
            }\
        }\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register dst,const fuku_operand& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x03 + 8*type);\
        emit_operand(fuku_get_index_by_register(dst), src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand& dst, fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x01 + 8*type);\
        emit_operand(fuku_get_index_by_register(src), dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand& dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        if (is_used_short_imm() && src.is_8()) {\
            emit_b(0x83);\
            emit_operand((fuku_register_index)type, dst);\
            emit_immediate_b(src);\
        }else{\
            emit_b(0x81);\
            emit_operand((fuku_register_index)type, dst);\
            emit_immediate_w(src);\
        }\
        gen_func_return(cap_id, cap_eflags)\
    } \
\
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x01 + 8*type);\
        emit_modrm(src, dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register dst,const fuku_immediate& src) { \
        gencleanerdata\
         if(is_used_short_eax() && dst == fuku_register::FUKU_REG_EAX) {\
            emit_b(0x05 + 8*type); \
            emit_immediate_dw(src);\
        } else {\
            if (is_used_short_imm() && src.is_8()) {\
                emit_b(0x83);\
                emit_modrm(type, dst);\
                emit_immediate_b(src);\
            }else{\
                emit_b(0x81);\
                emit_modrm(type, dst);\
                emit_immediate_dw(src);\
            }\
        }\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register dst,const fuku_operand& src) { \
        gencleanerdata\
        emit_b(0x03 + 8*type);\
        emit_operand(fuku_get_index_by_register(dst), src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand& dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x01 + 8*type);\
        emit_operand(fuku_get_index_by_register(src), dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand& dst,const fuku_immediate& src) { \
        gencleanerdata\
         if (is_used_short_imm() && src.is_8()) {\
            emit_b(0x83);\
            emit_operand((fuku_register_index)type, dst);\
            emit_immediate_b(src);\
        }else{\
            emit_b(0x81);\
            emit_operand((fuku_register_index)type, dst);\
            emit_immediate_dw(src);\
        }\
        gen_func_return(cap_id, cap_eflags)\
    } 

#define gen_func_body_arith_ex_one_op(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register src) { \
        gencleanerdata\
        emit_b(0xF6);\
        emit_modrm(type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (const fuku_operand& src) { \
        gencleanerdata\
        emit_b(0xF6);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
\
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0xF7);\
        emit_modrm(type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0xF7);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
\
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register src) { \
        gencleanerdata\
        emit_b(0xF7);\
        emit_modrm(type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand& src) { \
        gencleanerdata\
        emit_b(0xF7);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } 

#define gen_func_body_arith_incdec(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (fuku_register src) { \
        gencleanerdata\
        emit_b(0xFE);\
        emit_modrm(type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b) (const fuku_operand& src) { \
        gencleanerdata\
        emit_b(0xFE);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
\
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0xFF);\
        emit_modrm(type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0xFF);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
\
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register src) { \
        gencleanerdata\
        emit_b(0xFF);\
        emit_modrm(type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand& src) { \
        gencleanerdata\
        emit_b(0xFF);\
        emit_operand((fuku_register_index)type, src);\
        gen_func_return(cap_id, cap_eflags)\
    } 

#define gen_func_body_shift(name ,type, cap_id, cap_eflags) \
     genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_cl_b)(fuku_register dst) {\
       gencleanerdata\
       emit_b(0xD2);\
       emit_modrm(type, dst);\
       gen_func_return(cap_id, cap_eflags)\
     } \
     genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_cl_b)(const fuku_operand& dst) {\
       gencleanerdata\
       emit_b(0xD2);\
       emit_operand((fuku_register_index)type, dst);\
       gen_func_return(cap_id, cap_eflags)\
     } \
      genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b)(fuku_register dst, const fuku_immediate& src) {\
       gencleanerdata\
       if(src.get_immediate8() == 1) {\
          emit_b(0xD0); \
          emit_modrm(type, dst);\
       }else {\
          emit_b(0xC0); \
          emit_modrm(type, dst);\
          emit_immediate_b(src);\
       }\
       gen_func_return(cap_id, cap_eflags)\
     } \
      genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b)(const fuku_operand& dst, const fuku_immediate& src) {\
       gencleanerdata\
       if(src.get_immediate8() == 1) {\
          emit_b(0xD0); \
          emit_operand((fuku_register_index)type, dst);\
       }else {\
          emit_b(0xC0); \
          emit_operand((fuku_register_index)type, dst);\
          emit_immediate_b(src);\
       }\
       gen_func_return(cap_id, cap_eflags)\
     } \
\
      genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_cl_w)(fuku_register dst) {\
       gencleanerdata\
       emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
       emit_b(0xD3);\
       emit_modrm(type, dst);\
       gen_func_return(cap_id, cap_eflags)\
     } \
     genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_cl_w)(const fuku_operand& dst) {\
       gencleanerdata\
       emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
       emit_b(0xD3);\
       emit_operand((fuku_register_index)type, dst);\
       gen_func_return(cap_id, cap_eflags)\
     } \
      genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w)(fuku_register dst, const fuku_immediate& src) {\
       gencleanerdata\
       emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
       if(src.get_immediate8() == 1) {\
          emit_b(0xD1); \
          emit_modrm(type, dst);\
       }else {\
          emit_b(0xC1); \
          emit_modrm(type, dst);\
          emit_immediate_b(src);\
       }\
       gen_func_return(cap_id, cap_eflags)\
     } \
      genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w)(const fuku_operand& dst, const fuku_immediate& src) {\
       gencleanerdata\
       emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
       if(src.get_immediate8() == 1) {\
          emit_b(0xD1); \
          emit_operand((fuku_register_index)type, dst);\
       }else {\
          emit_b(0xC1); \
          emit_operand((fuku_register_index)type, dst);\
          emit_immediate_b(src);\
       }\
       gen_func_return(cap_id, cap_eflags)\
     } \
\
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_cl_dw)(fuku_register dst) {\
       gencleanerdata\
       emit_b(0xD3);\
       emit_modrm(type, dst);\
       gen_func_return(cap_id, cap_eflags)\
     } \
     genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_cl_dw)(const fuku_operand& dst) {\
       gencleanerdata\
       emit_b(0xD3);\
       emit_operand((fuku_register_index)type, dst);\
       gen_func_return(cap_id, cap_eflags)\
     } \
      genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw)(fuku_register dst, const fuku_immediate& src) {\
       gencleanerdata\
       if(src.get_immediate8() == 1) {\
          emit_b(0xD1); \
          emit_modrm(type, dst);\
       }else {\
          emit_b(0xC1); \
          emit_modrm(type, dst);\
          emit_immediate_b(src);\
       }\
       gen_func_return(cap_id, cap_eflags)\
     } \
      genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_b)(const fuku_operand& dst, const fuku_immediate& src) {\
       gencleanerdata\
       if(src.get_immediate8() == 1) {\
          emit_b(0xD1); \
          emit_operand((fuku_register_index)type, dst);\
       }else {\
          emit_b(0xC1); \
          emit_operand((fuku_register_index)type, dst);\
          emit_immediate_b(src);\
       }\
       gen_func_return(cap_id, cap_eflags)\
     } 

#define gen_func_body_bittest(name ,type, cap_id, cap_eflags) \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register dst, fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x0F);\
        emit_b(0x83 + 8*type);\
        emit_modrm(src, dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (fuku_register dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x0F);\
        emit_b(0xBA);\
        emit_modrm(type, dst);\
        emit_immediate_b(src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand& dst, fuku_register src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x0F);\
        emit_b(0x83 + 8*type);\
        emit_operand((fuku_register_index)type, dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_w) (const fuku_operand& dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(FUKU_PREFIX_OVERRIDE_DATA);\
        emit_b(0x0F);\
        emit_b(0xBA);\
        emit_operand((fuku_register_index)type, dst);\
        emit_immediate_b(src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x0F);\
        emit_b(0x83 + 8*type);\
        emit_modrm(src, dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (fuku_register dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(0x0F);\
        emit_b(0xBA);\
        emit_modrm(type, dst);\
        emit_immediate_b(src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand& dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x0F);\
        emit_b(0x83 + 8*type);\
        emit_operand((fuku_register_index)type, dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_dw) (const fuku_operand& dst,const fuku_immediate& src) { \
        gencleanerdata\
        emit_b(0x0F);\
        emit_b(0xBA);\
        emit_operand((fuku_register_index)type, dst);\
        emit_immediate_b(src);\
        gen_func_return(cap_id, cap_eflags)\
    } 
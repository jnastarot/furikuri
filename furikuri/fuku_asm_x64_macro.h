#pragma once

#define asm64_arith_add 0
#define asm64_arith_or  1
#define asm64_arith_adc 2
#define asm64_arith_sbb 3
#define asm64_arith_and 4
#define asm64_arith_sub 5
#define asm64_arith_xor 6
#define asm64_arith_cmp 7

#define asm64_arith_ex_not  2
#define asm64_arith_ex_neg  3
#define asm64_arith_ex_mul  4
#define asm64_arith_ex_imul 5
#define asm64_arith_ex_div  6
#define asm64_arith_ex_idiv 7

#define asm64_arith_inc 0
#define asm64_arith_dec 1

#define asm64_shift_rol 0
#define asm64_shift_ror 1
#define asm64_shift_rcl 2
#define asm64_shift_rcr 3
#define asm64_shift_shl 4
#define asm64_shift_shr 5
#define asm64_shift_sar 7

#define asm64_bittest_bt  4
#define asm64_bittest_bts 5
#define asm64_bittest_btr 6
#define asm64_bittest_btc 7


#define genname_asm64(prefix, sname, postfix) prefix ## sname ## postfix

#define genrettype_asm64 fuku_instruction

#define gencleanerdata \
     clear_space();

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
    } \
\
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_qw) (fuku_register dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x01 + 8*type);\
        emit_modrm(src, dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_qw) (fuku_register dst,const fuku_immediate& src) { \
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
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_qw) (fuku_register dst,const fuku_operand& src) { \
        gencleanerdata\
        emit_b(0x03 + 8*type);\
        emit_operand(fuku_get_index_by_register(dst), src);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_qw) (const fuku_operand& dst, fuku_register src) { \
        gencleanerdata\
        emit_b(0x01 + 8*type);\
        emit_operand(fuku_get_index_by_register(src), dst);\
        gen_func_return(cap_id, cap_eflags)\
    } \
    genrettype_asm86 fuku_asm_x86:: genname_asm86(_,name,_qw) (const fuku_operand& dst,const fuku_immediate& src) { \
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
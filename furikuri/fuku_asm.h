#pragma once

/* 
    rewrited from 
        https://github.com/v8/v8
*/


enum fuku_condition {
    no_condition    = -1,

    overflow        = 0,    jo   = 0,
    no_overflow     = 1,    jno  = 1,
    below           = 2,    jb   = 2,
    above_equal     = 3,    jae  = 3,    jnc = 3,
    equal           = 4,    je   = 4,    jz  = 4,
    not_equal       = 5,    jne  = 5,    jnz = 5,
    below_equal     = 6,    jna  = 6,    
    above           = 7,    jnbe = 7,    ja  = 7, 
    negative        = 8,    js   = 8,    
    positive        = 9,    jns  = 9,
    parity_even     = 10,   jp   = 10,   
    parity_odd      = 11,   jnp  = 11,   jpo = 11,
    less            = 12,   jnge = 12,   jl  = 12,
    greater_equal   = 13,   jnl  = 13,   
    less_equal      = 14,   jng  = 14,   jle = 14,
    greater         = 15,   jnle = 15,   jg  = 15,

    always          = 16,
    never           = 17,
};

enum operand_scale {
    operand_scale_1 = 0,
    operand_scale_2 = 1,
    operand_scale_4 = 2,
    operand_scale_8 = 3,
};


#include "fuku_asm_x86.h"
#include "fuku_asm_x64.h"
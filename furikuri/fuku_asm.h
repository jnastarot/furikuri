#pragma once

enum fuku_condition {
    no_condition = -1,
    overflow = 0,
    no_overflow = 1,
    below = 2,
    above_equal = 3,
    equal = 4,
    not_equal = 5,
    below_equal = 6,
    above = 7,
    negative = 8,
    positive = 9,
    parity_even = 10,
    parity_odd = 11,
    less = 12,
    greater_equal = 13,
    less_equal = 14,
    greater = 15,

    always = 16,
    never = 17,
};

enum operand_scale {
    operand_scale_1 = 0,
    operand_scale_2 = 1,
    operand_scale_4 = 2,
    operand_scale_8 = 3,
};


#include "fuku_asm_x86.h"
#include "fuku_asm_x64.h"
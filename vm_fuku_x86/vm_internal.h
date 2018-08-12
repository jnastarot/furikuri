#pragma once

#pragma pack(push,1)

enum j_condition {
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
};

struct context_regs {   
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;
};

struct context_flags {
    uint32_t _cf    : 1;
    uint32_t resv1  : 1;
    uint32_t _pf    : 1;
    uint32_t resv_2 : 1;
    uint32_t _af    : 1;
    uint32_t resv_3 : 1;
    uint32_t _zf    : 1;
    uint32_t _sf    : 1;
    uint32_t _tf    : 1;
    uint32_t _if    : 1;
    uint32_t _df    : 1;
    uint32_t _of    : 1;
    uint32_t _iopl  : 2;
    uint32_t _nt    : 1;
    uint32_t resv_4 : 1;
    uint32_t _rf    : 1;
    uint32_t _vm    : 1;
    uint32_t _ac    : 1;
    uint32_t _vif   : 1;
    uint32_t _vip   : 1;
    uint32_t _id    : 1;
    uint32_t resv_5 : 10;
};

struct global_context {
    context_regs  regs;
    
    union {
        context_flags flags;
        uint32_t d_flag;
    };
};

enum vm_opcode_86 {
    vm_opcode_86_pure,

    //sys
    vm_opcode_86_operand_create,
    vm_opcode_86_operand_set_base,
    vm_opcode_86_operand_set_index,
    vm_opcode_86_operand_set_scale,
    vm_opcode_86_operand_set_disp,

    //eip changers
    vm_opcode_86_jmp_local, /*jmp and jcc*/
    vm_opcode_86_jmp_external,
    vm_opcode_86_jcc_local,
    vm_opcode_86_jcc_external,

    vm_opcode_86_call_local,
    vm_opcode_86_call_external,

    vm_opcode_86_return,

    //stack changers
    vm_opcode_86_push,
    vm_opcode_86_pushad,
    vm_opcode_86_pushfd,

    vm_opcode_86_pop,
    vm_opcode_86_popad,
    vm_opcode_86_popfd,
    

    vm_opcode_86_mov,
    vm_opcode_86_lea,
    vm_opcode_86_xchg,

    //logical
    vm_opcode_86_cmp,
    vm_opcode_86_test,

    vm_opcode_86_and,
    vm_opcode_86_or,
    vm_opcode_86_xor,
    vm_opcode_86_not,
    
    //math
    vm_opcode_86_neg,
    vm_opcode_86_add,
    vm_opcode_86_sub,

    vm_opcode_86_mul,
    vm_opcode_86_div,



    vm_opcode_86_vm_exit,
};


struct vm_pure_code {

    struct {
        uint16_t code_len       : 4;
        uint16_t reloc_offset_1 : 4;
        uint16_t reloc_offset_2 : 4;
        uint16_t reserved_1     : 4;
    }info;

    uint8_t code[1];
};

struct vm_j_local_code {

    struct {
        uint8_t condition : 5;
        uint8_t back_jump : 1;
        uint8_t invert_condition : 2;
    }info;

    uint32_t offset;
};

struct vm_j_external_code {

    struct {
        uint8_t condition : 5;
        uint8_t back_jump : 1;
        uint8_t invert_condition : 2;
    }info;



};


#pragma pack(pop)
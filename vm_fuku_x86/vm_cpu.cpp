#include "stdafx.h"
#include "vm_cpu.h"


struct vm_context {
    global_context real_context;
    std::vector<uint32_t> operands;
    
    uint8_t * vm_code;

    struct {
        uint32_t saved_stack_pointer;
        uint32_t saved_regs[8];
        uint32_t saved_flags;
    }pure_call_context;
};


void vm_exit(vm_context& context, uint32_t ret_address);
void vm_pure(vm_context& context, uint8_t * instruction_ptr, uint32_t instruction_len);

#include "vm_macro.h"
#include "vm_operand.h"
#include "vm_stack.h"
#include "vm_control_flow.h"
#include "vm_movable.h"
#include "vm_arith.h"
#include "vm_logical.h"
#include "vm_flags_mods.h"


void WINAPI fuku_vm_handler(uint32_t original_stack) {

    vm_context context;

    memcpy(&context.real_context, (void*)(original_stack), sizeof(global_context));

    context.vm_code = (uint8_t*)(*(uint32_t*)(context.real_context.regs.esp + 4));

    context.real_context.regs.esp += sizeof(global_context) + 4;

    while (1) {

        vm_opcode_86 opcode = (vm_opcode_86)context.vm_code++[0];

        fprintf(stdout, "| EAX:%08x | ECX:%08x | EDX:%08x | EBX:%08x | ESP:%08x | EBP:%08x | ESI:%08x | EDI:%08x | FLAGS:%08x |\n",
            context.real_context.regs.eax,
            context.real_context.regs.ecx,
            context.real_context.regs.edx,
            context.real_context.regs.ebx,
            context.real_context.regs.esp,
            context.real_context.regs.ebp,
            context.real_context.regs.esi,
            context.real_context.regs.edi,
            context.real_context.d_flag
        );
        
        fprintf(stdout, "OPCODE : %02d %08x\n", opcode, context.vm_code -1);
        
        switch (opcode) {

        case vm_opcode_86_pure: {
            vm_pure_code * instruction = (vm_pure_code *)&context.vm_code[0];
            uint8_t inst_[16];

            memcpy(inst_, instruction->code, instruction->info.code_len);

            if (instruction->info.reloc_offset_1) {
                //*(uint32_t*)&shell_pure[19 + instruction->info.reloc_offset_1] += vm_context.image_base - vm_context.original_image_base;
            }

            if (instruction->info.reloc_offset_2) {
                // *(uint32_t*)&shell_pure[19 + instruction->info.reloc_offset_2] += vm_context.image_base - vm_context.original_image_base;
            }

            vm_pure(context, inst_, instruction->info.code_len);

            context.vm_code += instruction->info.code_len + 2;
            break;
        }

                                //operand vm
        case vm_opcode_86_operand_create: {
            vm_operand_create(context);
            break;
        }
        case vm_opcode_86_operand_set_base_link_reg: {
            vm_operand_set_base_link_reg(context);
            break;
        }
        case vm_opcode_86_operand_set_base: {
            vm_operand_set_base(context);
            break;
        }
        case vm_opcode_86_operand_set_index_scale: {
            vm_operand_set_index_scale(context);
            break;
        }
        case vm_opcode_86_operand_set_disp: {
            vm_operand_set_disp(context);
            break;
        }
        case vm_opcode_86_operand_set_relocatable: {

            break;
        }

                                                   //code graph changers
        case vm_opcode_86_jump_local: {
            vm_jump_local(context);
            break;
        }
        case vm_opcode_86_jump_external: {
            vm_jump_external(context);
            break;
        }
        case vm_opcode_86_call_local: {
            vm_call_local(context);
            break;
        }
        case vm_opcode_86_call_external: {
            vm_call_external(context);
            break;
        }
        case vm_opcode_86_return: {     
            vm_return(context);
            break;
        }

                                  //stack
        case vm_opcode_86_push: {
            vm_push(context);
            break;
        }
        case vm_opcode_86_pushad: {
            vm_pushad(context);
            break;
        }
        case vm_opcode_86_pushfd: {
            vm_pushfd(context);
            break;
        }
        case vm_opcode_86_pop: {
            vm_pop(context);
            break;
        }
        case vm_opcode_86_popad: {
            vm_popad(context);
            break;
        }
        case vm_opcode_86_popfd: {
            vm_popfd(context);
            break;
        }

                                 //movable
        case vm_opcode_86_mov: { //mov and lea
            vm_mov(context);
            break;
        }
        case vm_opcode_86_xchg: {
            vm_xchg(context);
            break;
        }


                                //arithmetic
        case vm_opcode_86_cmp: {
            vm_cmp(context);
            break;
        }
        case vm_opcode_86_neg: {
            vm_neg(context);
            break;
        }
        case vm_opcode_86_add: {
            vm_add(context);
            break;
        }
        case vm_opcode_86_adc: {
            vm_adc(context);
            break;
        }
        case vm_opcode_86_sub: {
            vm_sub(context);
            break;
        }
        case vm_opcode_86_sbb: {
            vm_sbb(context);
            break;
        }

                               //logical
        case vm_opcode_86_test: {
            vm_test(context);
            break;
        }
        case vm_opcode_86_and: {
            vm_and(context);
            break;
        }
        case vm_opcode_86_or: {
            vm_or(context);
            break;
        }
        case vm_opcode_86_xor: {
            vm_xor(context);
            break;
        }
        case vm_opcode_86_not: {
            vm_not(context);
            break;
        }
        case vm_opcode_86_shl: {
            vm_shl(context);
            break;
        }
        case vm_opcode_86_shr: {
            vm_shr(context);
            break;
        }
        case vm_opcode_86_sar: {
            vm_sar(context);
            break;
        }
        case vm_opcode_86_rol: {
            vm_rol(context);
            break;
        }
        case vm_opcode_86_ror: {
            vm_ror(context);
            break;
        }
        case vm_opcode_86_rcl: {
            vm_rcl(context);
            break;
        }
        case vm_opcode_86_rcr: {
            vm_rcr(context);
            break;
        }

                               //flag mods
        case vm_opcode_86_clc: {
            vm_clc(context);
            break;
        }
        case vm_opcode_86_cmc: {
            vm_cmc(context);
            break;
        }
        case vm_opcode_86_stc: {
            vm_stc(context);
            break;
        }
        case vm_opcode_86_cld: {
            vm_cld(context);
            break;
        }
        case vm_opcode_86_std: {
            vm_std(context);
            break;
        }

        default: {
          //  printf("unknown opcode!!\n");
          //  throw 0;
        }

        }

    }


}




DLLEXPORT __declspec (naked) void WINAPI fuku_vm_entry(void * pcode) {
    
    /*
    stack

    original eax
    ptr pcode
    ...
    */
   
    _asm {
        pushfd    //save flags
        pushad    //save regs

        push 0x40     //push PAGE_EXECURE_READWRITE
        push 0x1000   //push MEM_COMMIT
        push 0x1000   //push SIZE
        push 0        //push BASE ADDRESS
        call VirtualAlloc      //call VirtualAlloc

        xchg eax, esp //set new stack pointer
        add esp, 0x1000

        push eax
        call fuku_vm_handler
    }
}

void vm_exit(vm_context& context, uint32_t ret_address) {
    uint32_t original_esp_offset = (offsetof(vm_context, real_context.regs.esp));

    PUSH_VM(context, ret_address);/*ret address to original code*/

    vm_pushfd(context);//load flags
    vm_pushad(context);//load regs
    
    //virtual free 
    PUSH_VM(context, MEM_RELEASE);                           /*dwFreeType*/
    PUSH_VM(context, 0);			                         /*dwSize*/
    PUSH_VM(context, ((uint32_t(&context)) & 0xFFFFF000));   /*lpAddress*/

    context.operands.~vector();

    __asm {
        mov eax, context
        add eax, original_esp_offset
        mov esp, [eax]

        call VirtualFree

        popad
        popfd
        ret //->ret_address
    }
}


void vm_pure(vm_context& context,uint8_t * instruction_ptr, uint32_t instruction_len) {

    uint8_t shell_pure[] = {
        0x89, 0x25, 0, 0, 0, 0,             //mov [vm_context_imm],esp
        0xBC, 0, 0, 0, 0,                   //load original context pointer
        0x61,                               //popad
        0x9D,                               //popfd
        0x8B, 0x25, 0, 0, 0, 0,             //load original esp
        0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,    //db 16 DUP (90h) nops pure instruction
        0x89, 0x25, 0, 0, 0, 0,             //mov [saved_stack_pointer],esp
        0xBC, 0, 0, 0, 0,                   //mov esp,[saved_flags+4]
        0x9C,                               //pushfd
        0x60,                               //pushad
        0xBC, 0, 0, 0, 0,                   //mov esp,vm_context_imm
        0xC3                                //ret
    };

    uint8_t * shell_ptr = shell_pure;

    memcpy(&shell_pure[19], instruction_ptr, instruction_len);

    //load original context
    context.pure_call_context.saved_regs[7] = context.real_context.regs.eax;
    context.pure_call_context.saved_regs[6] = context.real_context.regs.ecx;
    context.pure_call_context.saved_regs[5] = context.real_context.regs.edx;
    context.pure_call_context.saved_regs[4] = context.real_context.regs.ebx;
    context.pure_call_context.saved_regs[3] = context.real_context.regs.esp;
    context.pure_call_context.saved_regs[2] = context.real_context.regs.ebp;
    context.pure_call_context.saved_regs[1] = context.real_context.regs.esi;
    context.pure_call_context.saved_regs[0] = context.real_context.regs.edi;
    context.pure_call_context.saved_flags   = context.real_context.d_flag;

    *(uint32_t*)&shell_pure[2]  = (uint32_t)&shell_pure[49];               //vm_context_imm
    *(uint32_t*)&shell_pure[7]  = (uint32_t)&context.pure_call_context.saved_regs[0];
    *(uint32_t*)&shell_pure[15] = (uint32_t)&context.pure_call_context.saved_regs[3];
    *(uint32_t*)&shell_pure[37] = (uint32_t)&context.pure_call_context.saved_stack_pointer; //vm_context_imm
    *(uint32_t*)&shell_pure[42] = ((uint32_t)&context.pure_call_context.saved_flags + 4);

	__asm {
		//save vm context
		pushfd
		pushad

		mov ecx, dword ptr shell_ptr

		call ecx //call shellcode


		popad
		popfd
	}

    //save original context
    context.real_context.regs.eax = context.pure_call_context.saved_regs[7];
    context.real_context.regs.ecx = context.pure_call_context.saved_regs[6];
    context.real_context.regs.edx = context.pure_call_context.saved_regs[5];
    context.real_context.regs.ebx = context.pure_call_context.saved_regs[4];
    context.real_context.regs.esp = context.pure_call_context.saved_stack_pointer;
    context.real_context.regs.ebp = context.pure_call_context.saved_regs[2];
    context.real_context.regs.esi = context.pure_call_context.saved_regs[1];
    context.real_context.regs.edi = context.pure_call_context.saved_regs[0];
    context.real_context.d_flag   = context.pure_call_context.saved_flags;
}



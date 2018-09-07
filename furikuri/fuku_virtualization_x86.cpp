#include "stdafx.h"
#include "fuku_virtualization_x86.h"

#include "..\vm_fuku_x86\vm_internal.h"

fuku_virtualization_x86::fuku_virtualization_x86() {}
fuku_virtualization_x86::~fuku_virtualization_x86(){}

char *reg_names[] = { "EAX",
"ECX",
"EDX",
"EBX",
"ESP",
"EBP",
"ESI",
"EDI" };


std::vector<fuku_vm_instruction> fuku_virtualization_x86::create_operand_reg(uint8_t r_reg, bool ptr) {
    std::vector<fuku_vm_instruction> operands;
    operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_create, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_operand_create)));

    operands.push_back(fuku_vm_instruction(ptr ? (uint8_t)vm_opcode_86_operand_set_base : (uint8_t)vm_opcode_86_operand_set_base_link_reg,
        std::vector<uint8_t>(std::initializer_list<uint8_t>({
            ptr ? (uint8_t)vm_opcode_86_operand_set_base : (uint8_t)vm_opcode_86_operand_set_base_link_reg, 
            r_reg
            })))
    );  

    printf(" &%s ", reg_names[r_reg]);

    return operands;
}

std::vector<fuku_vm_instruction> fuku_virtualization_x86::create_operand_disp(uint32_t disp) {
    std::vector<fuku_vm_instruction> operands;
    operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_create, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_operand_create)));

    if (disp) {
        operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_set_disp,
            std::vector<uint8_t>(std::initializer_list<uint8_t>({ vm_opcode_86_operand_set_disp,
                ((uint8_t*)&disp)[0] , ((uint8_t*)&disp)[1], ((uint8_t*)&disp)[2], ((uint8_t*)&disp)[3]
                })))
        );
    }

    printf(" DISP:%x ", disp);


    return operands;
}

std::vector<fuku_vm_instruction> fuku_virtualization_x86::create_operand_reg_disp(uint8_t base, uint32_t disp) {
    std::vector<fuku_vm_instruction> operands;
    operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_create, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_operand_create)));

    operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_set_base,
        std::vector<uint8_t>(std::initializer_list<uint8_t>({
            vm_opcode_86_operand_set_base,
            base
            })))
    );

    printf(" [%s", reg_names[base]);

    if (disp) {
        operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_set_disp,
            std::vector<uint8_t>(std::initializer_list<uint8_t>({ vm_opcode_86_operand_set_disp,
            ((uint8_t*)&disp)[0] , ((uint8_t*)&disp)[1], ((uint8_t*)&disp)[2], ((uint8_t*)&disp)[3]
                })))
        );

        printf(" + DISP:%x", disp);
    }

    printf(" ] ");

    return operands;
}

std::vector<fuku_vm_instruction> fuku_virtualization_x86::create_operand_sib(uint8_t base, uint8_t index, uint8_t scale, uint32_t disp) {
    std::vector<fuku_vm_instruction> operands;
    operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_create, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_operand_create)));

    operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_set_base,
        std::vector<uint8_t>(std::initializer_list<uint8_t>({
            vm_opcode_86_operand_set_base,
            base
            })))
    );

    printf(" [%s", reg_names[base]);

    if (scale < 1) { scale = 1; }


    operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_set_index_scale,
        std::vector<uint8_t>(std::initializer_list<uint8_t>({ vm_opcode_86_operand_set_index_scale, index , scale })))
    );

    printf(" + %s * %d", reg_names[index] , scale);


    if (disp) {
        operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_set_disp,
            std::vector<uint8_t>(std::initializer_list<uint8_t>({ vm_opcode_86_operand_set_disp,
            ((uint8_t*)&disp)[0] , ((uint8_t*)&disp)[1], ((uint8_t*)&disp)[2], ((uint8_t*)&disp)[3]
                })))
        );
        printf(" + DISP:%x", disp);
    }


    printf(" ] ");

    return operands;
}

std::vector<fuku_vm_instruction> fuku_virtualization_x86::create_operand_sib(uint8_t index, uint8_t scale, uint32_t disp) {
    std::vector<fuku_vm_instruction> operands;
    operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_create, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_operand_create)));


    if (scale < 1) { scale = 1; }


    operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_set_index_scale,
        std::vector<uint8_t>(std::initializer_list<uint8_t>({ vm_opcode_86_operand_set_index_scale, index , scale })))
    );

    printf(" [%s * %d", reg_names[index], scale);

    if (disp) {
        operands.push_back(fuku_vm_instruction(vm_opcode_86_operand_set_disp,
            std::vector<uint8_t>(std::initializer_list<uint8_t>({ vm_opcode_86_operand_set_disp,
            ((uint8_t*)&disp)[0] , ((uint8_t*)&disp)[1], ((uint8_t*)&disp)[2], ((uint8_t*)&disp)[3]
                })))
        );

        printf(" + DISP:%x", disp);
    }


    printf(" ]");

    return operands;
}


void fuku_virtualization_x86::get_operands(const _DInst& inst,const fuku_instruction& line, std::vector<fuku_vm_instruction>& operands) {

    std::vector<fuku_vm_instruction> current_op;

    operands.clear();

    for (int i = 0; i < OPERANDS_NO; i++) {
        if (i != 0 && inst.ops[i].type) { printf(","); }

        switch (inst.ops[i].type) {
        
        case O_NONE: {
            break;
        }

        case O_REG: { //index holds global register index.
            current_op = create_operand_reg(inst.ops[i].index & 0x0F, i == 0 ? false : true);
            break;
        }

        case O_IMM: { //instruction.imm.
            current_op = create_operand_disp(inst.imm.dword);
            break;
        }

        case O_IMM1: { //instruction.imm.ex.i1.

            break;
        }

        case O_IMM2: { //instruction.imm.ex.i2.

            break;
        }

        case O_DISP: {//memory dereference with displacement only, instruction.disp.
            current_op = create_operand_disp(inst.disp);
            break;
        }

        case O_MEM: {//simple memory dereference with optional displacement (a single register memory dereference).
            current_op = create_operand_reg_disp(inst.ops[i].index & 0x0F, inst.disp);
            break;
        }
        case O_SMEM: { //complex memory dereference (optional fields: s/i/b/disp).
            if (inst.base == R_NONE) {
                current_op = create_operand_sib(inst.ops[i].index & 0x0F, inst.scale, inst.disp);
            }
            else {
                current_op = create_operand_sib(inst.base & 0x0F, inst.ops[i].index & 0x0F, inst.scale, inst.disp);
            }                
            break;
        }
        case O_PC: { //the relative address of a branch instruction (instruction.imm.addr).         
            current_op = create_operand_disp((uint32_t)INSTRUCTION_GET_TARGET(&inst));
            break;
        }
        case O_PTR: {//the absolute target address of a far branch instruction (instruction.imm.ptr.seg/off).
            break;
        }

        }

        if (current_op.size()) {
            operands.insert(operands.end(), current_op.begin(), current_op.end());
        }

        current_op.clear();
    }

    printf("\n");
}

uint8_t fuku_virtualization_x86::get_ext_code(const _DInst& inst) {
    
    vm_ops_ex_code ex_code(0,0,0,0);

    if (inst.ops[0].type != O_NONE) {

        if (inst.ops[1].type != O_NONE) {
            ex_code.info.src_is_ptr = inst.ops[1].type == O_SMEM || inst.ops[1].type == O_MEM || inst.ops[1].type == O_DISP ;
            ex_code.info.dst_is_ptr = inst.ops[0].type == O_SMEM || inst.ops[0].type == O_MEM || inst.ops[0].type == O_DISP || inst.ops[0].type == O_REG;
            ex_code.info.op_1_size = inst.ops[0].size / 8;
            ex_code.info.op_2_size = inst.ops[1].size / 8;


            if (ex_code.info.dst_is_ptr) {
                printf(" [DST PTR] ", ex_code.info.dst_is_ptr);
            }
            if (ex_code.info.src_is_ptr) {
                printf(" [SRC PTR] ", ex_code.info.src_is_ptr);
            }
            
        }
        else {
            ex_code.info.src_is_ptr = inst.ops[0].type == O_SMEM || inst.ops[0].type == O_MEM || inst.ops[0].type == O_DISP || inst.ops[0].type == O_REG;
            ex_code.info.op_1_size = inst.ops[0].size / 8;

            printf(" [SRC PTR] ", ex_code.info.src_is_ptr);
        } 
    }

    

    return ex_code.ex_code;
}

fuku_vm_result fuku_virtualization_x86::build_bytecode(fuku_analyzed_code& code, 
    std::vector<fuku_code_relocation>& relocation_table, std::vector<fuku_code_association>& association_table, 
    uint64_t destination_virtual_address) {

    association_table.clear();
    lines.clear();

    _CodeInfo code_info = { 0, 0, 0, 0 ,
        code.arch == fuku_arch::fuku_arch_x32 ? _DecodeType::Decode32Bits : _DecodeType::Decode64Bits,
        0
    };

    _DInst current_inst;
    uint32_t used_inst;
    uint64_t current_va = destination_virtual_address;
    std::vector<fuku_vm_instruction> operands;

    for (size_t line_idx = 0; line_idx < code.lines.size(); line_idx++) {
        auto& current_line = code.lines[line_idx];
        operands.clear();

       // if (current_line.get_source_virtual_address() == 0x401098) { __debugbreak(); }
        
        code_info.code = current_line.get_op_code();
        code_info.codeLen = current_line.get_op_length();
        code_info.codeOffset = current_line.get_virtual_address();

        distorm_decompose64(&code_info, &current_inst, 1, &used_inst);

        std::vector<fuku_vm_instruction> vm_lines;

        printf("[ %I64x ] ", current_line.get_source_virtual_address());

        switch (current_line.get_type()) {

        case  I_JO: case  I_JNO:
        case  I_JB: case  I_JAE:
        case  I_JZ: case  I_JNZ:
        case  I_JBE:case  I_JA:
        case  I_JS: case  I_JNS:
        case  I_JP: case  I_JNP:
        case  I_JL: case  I_JGE:
        case  I_JLE:case  I_JG: 
        case  I_JMP: {

            printf("JMP ");

            vm_jump_code jump_code;
            
            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());

            if (current_line.get_type() == I_JMP) {
                jump_code.condition = 8;
                jump_code.invert_condition = 0;
            }
            else {
                uint8_t jmp_cc;

                if (current_line.get_op_code()[current_line.get_op_pref_size()] == 0x0F) {
                    jmp_cc = (current_line.get_op_code()[current_line.get_op_pref_size() + 1] & 0x0F);
                }
                else {
                    jmp_cc = (current_line.get_op_code()[current_line.get_op_pref_size()] & 0x0F);
                }
                
                jump_code.condition = jmp_cc / 2;
                jump_code.invert_condition = jmp_cc & 1;
            }

            if (current_line.get_link_label_id()) {
                vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_jump_local,
                    std::vector<uint8_t>(std::initializer_list<uint8_t>({  (uint8_t)vm_opcode_86_jump_local, jump_code.j_code, ex_code })))
                );

                vm_lines[vm_lines.size() - 2].set_link_label_id(current_line.get_link_label_id());
            }
            else {
                vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_jump_external,
                    std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_jump_external, jump_code.j_code, ex_code })))
                );

                vm_lines[vm_lines.size() - 2].set_original(&current_line);
            }

            break;
        }

        case I_CALL: {
            printf("CALL ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());

            if (current_line.get_link_label_id()) {
                vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_call_local,
                    std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_call_local, ex_code }))));

                vm_lines[vm_lines.size() - 2].set_link_label_id(current_line.get_link_label_id());
            }
            else {
                vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_call_external,
                    std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_call_external, ex_code }))));

                if (current_inst.ops[0].type == O_DISP) {
                    vm_lines[vm_lines.size() - 2].set_original(&current_line);
                }

            }

            break;
        }

        case I_RET: {
            printf("RET ");

            std::vector<fuku_vm_instruction> ops = create_operand_disp(current_inst.imm.dword);
            vm_lines.insert(vm_lines.end(), ops.begin(), ops.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_return, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_return)));
            break;
        }
            
        case I_PUSH: {
            printf("PUSH ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_push, 
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_push, ex_code })))
            );
            break;
        }

        case I_PUSHA: {
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_pushad, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_pushad)));
            break;
        }

        case I_PUSHF: {
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_pushfd, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_pushfd)));
            break;
        }

        case I_POP: {
            printf("POP ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_pop,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_pop, ex_code })))
            );
            break;
        }

        case I_POPA: {
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_popad, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_popad)));
            break;
        }

        case I_POPF: {
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_popfd, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_popfd)));
            break;
        }

        case I_MOV: {
            printf("MOV ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_mov,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_mov, ex_code })))
            );
            break;
        }
                    
        case I_LEA: {
            printf("LEA ");

            uint8_t ex_code = get_ext_code(current_inst);
            (*(vm_ops_ex_code*)&ex_code).info.src_is_ptr = false;
            (*(vm_ops_ex_code*)&ex_code).info.op_2_size  = (*(vm_ops_ex_code*)&ex_code).info.op_1_size;

            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_mov,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_mov, ex_code })))
            );
            break;
        }


        case I_XCHG: {
            printf("XCHG ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_xchg,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_xchg, ex_code })))
            );
            break;
        }

        case I_TEST: {
            printf("TEST ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_test,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_test, ex_code })))
            );
            break;
        }

        case I_AND: {
            printf("AND ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_and,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_and, ex_code })))
            );
            break;
        }

        case I_OR: {
            printf("OR ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_or,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_or, ex_code })))
            );
            break;
        }
        case I_XOR: {
            printf("XOR ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_xor,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_xor, ex_code })))
            );
            break;
        }
        case I_NOT: {
            printf("NOT ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_not,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_not, ex_code })))
            );
            break;
        }
        case I_SHL: {
            printf("SHL ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_shl,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_shl, ex_code })))
            );
            break;
        }
        case I_SHR: {
            printf("SHR ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_shr,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_shr, ex_code })))
            );
            break;
        }
                    /*
        case I_SAR: {

            break;
        }
        case I_ROL: {

            break;
        }
        case I_ROR: {

            break;
        }
        case I_RCL: {

            break;
        }
        case I_RCR: {

            break;
        }
*/

        case I_NEG: {
            printf("NEG ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_neg,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_neg, ex_code })))
            );
            break;
        }
/*
        case I_CMP: {
            printf("CMP ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_cmp,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_cmp, ex_code })))
            );
            break;
        }
  */      
        case I_ADD: {
            printf("ADD ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_add,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_add, ex_code })))
            );
            break;
        }

        case I_ADC: {
            printf("ADC ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_adc,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_adc, ex_code })))
            );
            break;
        }

        case I_SUB: {
            printf("SUB ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_sub,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_sub, ex_code })))
            );
            break;
        }

        case I_SBB: {
            printf("SBB ");

            uint8_t ex_code = get_ext_code(current_inst);
            get_operands(current_inst, current_line, operands);

            vm_lines.insert(vm_lines.end(), operands.begin(), operands.end());
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_sbb,
                std::vector<uint8_t>(std::initializer_list<uint8_t>({ (uint8_t)vm_opcode_86_sbb, ex_code })))
            );
            break;
        }
/*
        case I_MUL: {

            break;
        }

        case I_IMUL: {

            break;
        }
        case I_DIV: {

            break;
        }

        case I_IDIV: {

            break;
        }
*/
        case I_CLC: {
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_clc, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_clc)));
            break;
        }

        case I_CMC: {
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_cmc, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_cmc)));
            break;
        }

        case I_STC: {
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_stc, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_stc)));
            break;
        }

        case I_CLD: {
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_cld, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_cld)));
            break;
        }

        case I_STD: {
            vm_lines.push_back(fuku_vm_instruction(vm_opcode_86_std, std::vector<uint8_t>(1, (uint8_t)vm_opcode_86_std)));
            break;
        }

        default: {
            printf("PURE \n");

            vm_pure_code pure_code;
            pure_code.info.code_len = current_line.get_op_length();
            pure_code.info.reloc_offset_1 = current_line.get_relocation_f_imm_offset();
            pure_code.info.reloc_offset_2 = current_line.get_relocation_s_imm_offset();
            
            fuku_vm_instruction vm_pure(vm_opcode_86_pure);
            vm_pure.add_pcode((uint8_t)vm_opcode_86_pure);
            vm_pure.add_pcode(*(uint16_t*)(&pure_code.info));
            
            for (size_t i = 0; i < current_line.get_op_length();i++) {
                vm_pure.add_pcode(current_line.get_op_code()[i]); 
            }

            vm_lines.push_back(vm_pure);
            break;
        }

        }

        if (vm_lines.size() == 0) { __debugbreak(); }

        vm_lines[0].set_source_virtual_address(current_line.get_source_virtual_address());
        vm_lines[0].set_label_id(current_line.get_label_id());

        lines.insert(lines.end(), vm_lines.begin(), vm_lines.end());
    }

    post_process_lines(destination_virtual_address);

    for (auto& line : lines) {
        if (line.get_source_virtual_address() != -1) {
            association_table.push_back({ line.get_source_virtual_address() , line.get_virtual_address()});
        }
    }

    return fuku_vm_result::fuku_vm_ok;
}

void fuku_virtualization_x86::post_process_lines(uint64_t destination_virtual_address) {
    
    std::vector<uint32_t> label_cache;

    {
        uint64_t line_va = destination_virtual_address;
        for (uint32_t idx = 0; idx < this->lines.size(); idx++) {
            auto& line = lines[idx];

            if (line.get_label_id()) {
                label_cache.push_back(idx);
            }

            line.set_virtual_address(line_va);
            line_va += line.get_pcode().size();
        }

        std::sort(label_cache.begin(), label_cache.end(), [&, this](uint32_t lhs, uint32_t rhs) {
            return this->lines[lhs].get_label_id() < this->lines[rhs].get_label_id();
        });
    }

    for (auto& line : lines) {

        switch (line.get_type()) {
        
        case vm_opcode_86_operand_set_disp: {

            if (line.get_link_label_id()) {
                (*(uint32_t*)&line.get_pcode()[1]) = lines[label_cache[line.get_link_label_id() - 1]].get_virtual_address();
            }

            break;
        }



        default: {
            break;
        }

        }
    }
}

std::vector<uint8_t> fuku_virtualization_x86::create_vm_jumpout(uint64_t src_address, uint64_t dst_address, uint64_t vm_entry_address, std::vector<fuku_code_relocation>& relocation_table) const {

    std::vector<uint8_t> j_out;
    j_out.resize(10);
    
    j_out[0] = 0x68;
    j_out[5] = 0xE9;

    *(uint32_t*)&j_out[1] = (uint32_t)dst_address;
    *(uint32_t*)&j_out[6] = uint32_t(vm_entry_address - (src_address + 5)) - 5;

    relocation_table.push_back({ src_address + 1 , 0});

    return j_out;
}

std::vector<uint8_t> fuku_virtualization_x86::get_bytecode() const {
    std::vector<uint8_t> lines_dump;
    size_t dump_size = 0;

    for (size_t line_idx = 0; line_idx < lines.size(); line_idx++) { dump_size += lines[line_idx].get_pcode().size(); }
    lines_dump.resize(dump_size);

    size_t opcode_caret = 0;
    for (auto &line : lines) {
        memcpy(&lines_dump.data()[opcode_caret], line.get_pcode().data(), line.get_pcode().size());
        opcode_caret += line.get_pcode().size();
    }

    return lines_dump;
}

fuku_arch fuku_virtualization_x86::get_target_arch() const { 
    return fuku_arch::fuku_arch_x32;
}


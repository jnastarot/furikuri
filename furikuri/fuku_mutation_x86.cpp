#include "stdafx.h"
#include "fuku_mutation_x86.h"

#define ISNT_LAST (lines.size() > current_line_idx+1)

fuku_mutation_x86::fuku_mutation_x86(const ob_fuku_sensitivity& settings, fuku_obfuscator * obfuscator)
: settings(settings), obfuscator(obfuscator){}

fuku_mutation_x86::~fuku_mutation_x86() {

}

void fuku_mutation_x86::obfuscate_lines(std::vector<fuku_instruction>& lines, unsigned int recurse_idx) {

    std::vector<fuku_instruction> obf_lines;

    //obfuscate
    for (size_t line_idx = 0; line_idx < lines.size(); line_idx++) {
        std::vector<fuku_instruction> single_line;
    
        fukutation(lines, line_idx, single_line);

        unsigned int recurse_idx_up = 0;
        if (recurse_idx == -1) {
            recurse_idx_up = rand() % settings.complexity + 1;
        }
        else {
            recurse_idx_up = recurse_idx - 1;
        }

        if (recurse_idx_up) {
            obfuscate_lines(single_line, recurse_idx_up);
        }

        if (recurse_idx == -1) {
            single_line[0].set_label_id(lines[line_idx].get_label_id());
            single_line[0].set_source_virtual_address(lines[line_idx].get_source_virtual_address());
        }


        obf_lines.insert(obf_lines.end(), single_line.begin(), single_line.end());
    }

    lines = obf_lines;
}

void fuku_mutation_x86::obfuscate(std::vector<fuku_instruction>& lines) {
    obfuscate_lines(lines, -1);
}




void fuku_mutation_x86::generate_junk(std::vector<uint8_t>& junk, size_t junk_size) {



    
}




void fuku_mutation_x86::fukutation(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {


    if (FUKU_GET_CHANCE(settings.junk_chance)) {
        fuku_junk(lines, current_line_idx, out_lines);
    }

    if (FUKU_GET_CHANCE(settings.mutate_chance)) {
        switch (lines[current_line_idx].get_type()) {

        case I_PUSH: {
            if (!fukutate_push(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_POP: {
            if (!fukutate_pop(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }


        case I_ADD: {
            if (!fukutate_add(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_SUB: {
            if (!fukutate_sub(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_XOR: {
            if (!fukutate_xor(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_AND: {
            if (!fukutate_and(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }


        case I_INC: {
            if (!fukutate_inc(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_DEC: {
            if (!fukutate_dec(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_TEST: {
            if (!fukutate_test(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }
        case I_CMP: {
            if (!fukutate_cmp(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_JMP: {
            if (!fukutate_jmp(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case  I_JO: case  I_JNO:
        case  I_JB: case  I_JAE:
        case  I_JZ: case  I_JNZ:
        case  I_JBE:case  I_JA:
        case  I_JS: case  I_JNS:
        case  I_JP: case  I_JNP:
        case  I_JL: case  I_JGE:
        case  I_JLE:case  I_JG: {
            if (!fukutate_jcc(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }


        case I_RET: {
            if (!fukutate_ret(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        default: {
            out_lines.push_back(lines[current_line_idx]);
            break;
        }
        }
    }
    else {
        out_lines.push_back(lines[current_line_idx]);
    }
}


bool fuku_mutation_x86::fukutate_push(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];
    const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

    if (code[0] == 0x6A || 
        code[0] == 0x68 ) {

        uint32_t val;

        if (code[0] == 0x6A) {
            val = *(uint8_t*)&code[1];
        }
        else {
            val = *(uint32_t*)&code[1];
        }

        out_lines.push_back(f_asm.sub(fuku_reg86::r_ESP, fuku_immediate86(4)).set_useless_flags(target_line.get_useless_flags()));
        out_lines.push_back(f_asm.mov(fuku_operand86(fuku_reg86::r_ESP,operand_scale::operand_scale_1),fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
        

        /*
        //sub esp,4
        //mov [esp],value
       */
        return true;
    } else if ((code[0] & 0x50) == 0x50) {
        fuku_reg86 reg = fuku_reg86( code[0] & 0x0F);

        out_lines.push_back(f_asm.sub(fuku_reg86::r_ESP, fuku_immediate86(4)).set_useless_flags(target_line.get_useless_flags()));
        out_lines.push_back(f_asm.mov(fuku_operand86(fuku_reg86::r_ESP,operand_scale::operand_scale_1), reg).set_useless_flags(target_line.get_useless_flags()));
        
        /*
        //sub esp,4
        //mov [esp],reg
       */
        return true;
    }
   

    return false;
}
bool fuku_mutation_x86::fukutate_pop(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {


    auto& target_line = lines[current_line_idx];
    const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

     if ((code[0] & 0x50) == 0x50) {
        fuku_reg86 reg = fuku_reg86(code[0] % 8);

        
        out_lines.push_back(f_asm.mov(reg,fuku_operand86(fuku_reg86::r_ESP, operand_scale::operand_scale_1)).set_useless_flags(target_line.get_useless_flags()));
        out_lines.push_back(f_asm.add(fuku_reg86::r_ESP, fuku_immediate86(4)).set_useless_flags(target_line.get_useless_flags()));

        /*
        //mov reg,[esp]
        //add esp,4
        */
        return true;
    }

    return false;
}
bool fuku_mutation_x86::fukutate_add(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {


    auto& target_line = lines[current_line_idx];

    if ( (target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags()) {
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if (code[0] == 0x05 ||  //add reg,imm
            ((code[0] == 0x81 || code[0] == 0x83) && (code[1] >= 0xC0 && code[1] < 0xC8)) ) {

            fuku_reg86 reg1;
            uint32_t val;

            if (code[0] == 0x05) {
                reg1 = fuku_reg86::r_EAX;
                val = *(uint32_t*)&code[1];
            }
            else {
                reg1 = fuku_reg86(code[1] - 0xC0);
                if (code[0] == 0x81) {
                    val = *(uint32_t*)&code[2];
                }
                else {
                    val = *(int8_t*)&code[2];
                }
            }


            switch (FUKU_GET_RAND(1, 2)) {
            case 1: {
                unsigned int passes_number = FUKU_GET_RAND(2, 4);
                uint32_t current_val = 0;

                for (unsigned int pass = 0; pass < passes_number; pass++ ) {

                    switch (FUKU_GET_RAND(1, 2)) {

                    case 1: {
                        if (pass + 1 < passes_number) {
                            uint32_t rand_val = FUKU_GET_RAND(0, 0xFFFFFFFF);
                            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(rand_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val -= rand_val;
                        }
                        else {
                            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(current_val - val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val -= current_val - val;
                        }
                        break;
                    }
                    case 2: {
                        if (pass + 1 < passes_number) {
                            uint32_t rand_val = FUKU_GET_RAND(0, 0xFFFFFFFF);
                            out_lines.push_back(f_asm.add(reg1, fuku_immediate86(rand_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val += rand_val;
                        }
                        else {
                            out_lines.push_back(f_asm.add(reg1, fuku_immediate86(val - current_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val += val - current_val;                       
                        }
                        break;
                    }
                    }
                }
                break;
            }

            case 2: {
                out_lines.push_back(f_asm.sub(reg1, fuku_immediate86((-(int32_t)val))).set_useless_flags(target_line.get_useless_flags()));
                break;
            }
            }
            

            return true;
        }
    }

    return false;
}
bool fuku_mutation_x86::fukutate_sub(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];

    if ((target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags()) {
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if (code[0] == 0x2D ||  //sub reg,imm
            ((code[0] == 0x81 || code[0] == 0x83) && (code[1] >= 0xE8 && code[1] < 0xF0))) {

            fuku_reg86 reg1;
            uint32_t val;

            if (code[0] == 0x2D) {
                reg1 = fuku_reg86::r_EAX;
                val = *(uint32_t*)&code[1];
            }
            else {
                reg1 = fuku_reg86(code[1] - 0xE8);
                if (code[0] == 0x81) {
                    val = *(uint32_t*)&code[2];
                }
                else {
                    val = *(int8_t*)&code[2];
                }
            }
            val = -(int32_t)val;

            switch (FUKU_GET_RAND(1, 2)) {
            case 1: {
                unsigned int passes_number = FUKU_GET_RAND(2, 4);
                uint32_t current_val = 0;

                for (unsigned int pass = 0; pass < passes_number; pass++) {

                    switch (FUKU_GET_RAND(1, 2)) {

                    case 1: {
                        if (pass + 1 < passes_number) {
                            uint32_t rand_val = FUKU_GET_RAND(0, 0xFFFFFFFF);
                            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(rand_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val -= rand_val;
                        }
                        else {
                            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(current_val - val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val -= current_val - val;
                        }
                        break;
                    }
                    case 2: {
                        if (pass + 1 < passes_number) {
                            uint32_t rand_val = FUKU_GET_RAND(0, 0xFFFFFFFF);
                            out_lines.push_back(f_asm.add(reg1, fuku_immediate86(rand_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val += rand_val;
                        }
                        else {
                            out_lines.push_back(f_asm.add(reg1, fuku_immediate86(val - current_val)).set_useless_flags(target_line.get_useless_flags()));
                            current_val += val - current_val;
                        }
                        break;
                    }
                    }
                }
                break;
            }

            case 2: {
                out_lines.push_back(f_asm.sub(reg1, fuku_immediate86((-(int32_t)val))).set_useless_flags(target_line.get_useless_flags()));
                break;
            }
            }


            return true;
        }
    }

    return false;
}
bool fuku_mutation_x86::fukutate_xor(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    //A xor B = ((neg A) and B) or (A and (neg B))


    auto& target_line = lines[current_line_idx];

    if ((target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags()) {
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if (
            (code[0] == 0x31 || code[0] == 0x33) && code[1] >= 0xC0) { //xor reg_dw, reg_dw
            fuku_reg86 reg1 = fuku_reg86((code[1] - 0xC0) % 8);
            fuku_reg86 reg2 = fuku_reg86((code[1] - 0xC0) / 8);
            fuku_reg86 reg3 = fuku_reg86::r_EAX;

            if (code[0] == 0x33) { std::swap(reg1, reg2); }


            for (reg3 = fuku_reg86::r_EAX; reg3 < fuku_reg86::r_EBX; reg3 = fuku_reg86(reg3 + 1)) {}

            out_lines.push_back(f_asm.push(reg3).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.mov(reg3, reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.not_(reg3).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.and_(reg3, reg2).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.push(reg3).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.mov(reg3, reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.not_(reg3).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.and_(reg3, reg1).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.pop(reg1).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.or_(reg1, reg3).set_useless_flags(target_line.get_useless_flags()));
            
            out_lines.push_back(f_asm.pop(reg3).set_useless_flags(target_line.get_useless_flags()));

            /*
            push reg3
            
            mov reg3, reg1
            not reg3
            and reg3, reg2

            push reg3

            mov reg3, reg2
            not reg3
            and reg3, reg1

            pop reg1

            or reg1, reg3

            pop reg3
            */

            return true;
        }
        else if (((code[0] == 0x81 || code[0] == 0x83) && (code[1] & 0xF0) == 0xF0 && code[1] < 0xF8) || code[1] == 0x35) { //xor reg_dw , val //xor reg_b , val
            fuku_reg86 reg1;
            fuku_reg86 reg2;
            uint32_t val;

            if (code[1] == 0x35) {
                reg1 = fuku_reg86::r_EAX;
                reg2 = fuku_reg86::r_ECX;
                val = *(uint32_t*)&code[1];
            }
            else {
                reg1 = fuku_reg86((code[1] - 0xF0) & 0x0F);
                reg2 = fuku_reg86::r_ECX;

                if (code[0] == 0x83) {
                    val = *(uint8_t*)&code[2];
                }
                else {
                    val = *(uint32_t*)&code[2];
                }

                for (reg2 = fuku_reg86::r_EAX; reg2 < fuku_reg86::r_EBX; reg2 = fuku_reg86(reg2 + 1)) {}
            }
        
            out_lines.push_back(f_asm.push(reg2).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.mov(reg2, reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.not_(reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.and_(reg2, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.push(reg2).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.mov(reg2, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.not_(reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.and_(reg2, reg1).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.pop(reg1).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.or_(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));

            out_lines.push_back(f_asm.pop(reg2).set_useless_flags(target_line.get_useless_flags()));

            /*
            push reg2

            mov reg2, reg1
            not reg2
            and reg2, imm

            push reg2

            mov reg2, imm
            not reg2
            and reg2, reg1

            pop reg1

            or reg1, reg2

            pop reg2
            */

            return true;
        }

    }


    return false;
}
bool fuku_mutation_x86::fukutate_and(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    //A and B = (A or B) xor A xor B

    auto& target_line = lines[current_line_idx];

    if ((target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags()) {
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if (
            (code[0] == 0x21 || code[0] == 0x23) && code[1] >= 0xC0) { //and reg_dw, reg_dw
            fuku_reg86 reg1 = fuku_reg86( (code[1] - 0xC0) % 8);
            fuku_reg86 reg2 = fuku_reg86( (code[1] - 0xC0) / 8);
            fuku_reg86 reg3 = fuku_reg86::r_EAX;

            if (code[0] == 0x23) {  std::swap(reg1, reg2); }

            for (reg3 = fuku_reg86::r_EAX; reg3 < fuku_reg86::r_EBX; reg3 = fuku_reg86(reg3+1)) {}

            out_lines.push_back(f_asm.push(reg3).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.mov(reg3, reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.or_(reg1,reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.xor_(reg1, reg3).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.xor_(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg3).set_useless_flags(target_line.get_useless_flags()));

            /*
            push reg3
            mov reg3, reg1
            or  reg1, reg2
            xor reg1, reg3
            xor reg1, reg2
            pop reg3
            */

            return true;
        }
        else if (( (code[0] == 0x81 || code[0] == 0x83) && (code[1] & 0xF0) == 0xE0 && code[1] < 0xE8) || code[1] == 0x25) { //and reg_dw , val //and reg_b , val
            fuku_reg86 reg1;
            fuku_reg86 reg2;
            uint32_t val;

            if (code[1] == 0x25) {
                reg1 = fuku_reg86::r_EAX;
                reg2 = fuku_reg86::r_ECX;
                val = *(uint32_t*)&code[1];
            }
            else {
                reg1 = fuku_reg86((code[1] - 0xE0) & 0x0F);
                reg2 = fuku_reg86::r_ECX;

                if (code[0] == 0x83) {
                    val = *(uint8_t*)&code[2];
                }
                else {
                    val = *(uint32_t*)&code[2];
                }

                for (reg2 = fuku_reg86::r_EAX; reg2 < fuku_reg86::r_EBX; reg2 = fuku_reg86(reg2 + 1)) {}
            }
           
            out_lines.push_back(f_asm.push(reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.mov(reg2, reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.or_(reg1, val).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.xor_(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.xor_(reg1, val).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg2).set_useless_flags(target_line.get_useless_flags()));

            /*
            push reg2
            mov reg2, reg1
            or  reg1, val
            xor reg1, reg2
            xor reg1, val
            pop reg2
            */

            return true;
        }

        return false;
    }

    return false;
}

bool fuku_mutation_x86::fukutate_inc(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];

    if ((target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags()) { 
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if ((code[0] & 0xF0) == 0x40) { //inc reg_dw 
            fuku_reg86 reg = fuku_reg86(code[0] & 0x0F);
            fuku_instruction l_res;

            /*
            (add reg,FFFFFFFF) or (sub reg,1)
            */

            if (FUKU_GET_CHANCE(50.f)) {
                l_res = f_asm.add(reg, fuku_immediate86(1));
            }
            else {
                l_res = f_asm.sub(reg, fuku_immediate86(0xFFFFFFFF));
            }

            l_res.set_useless_flags(target_line.get_useless_flags());

            out_lines.push_back(l_res);

            return true;
        }
        
        return false;
    }

    return false;
}
bool fuku_mutation_x86::fukutate_dec(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];

    if ((target_line.get_modified_flags() & target_line.get_useless_flags()) == target_line.get_modified_flags()) {
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        if ((code[0] & 0xF0) == 0x40) { //dec reg_dw
            fuku_reg86 reg = fuku_reg86((code[0] & 0x0F) - 8);
            fuku_instruction l_res;

            /*
            (add reg,1) or (sub reg,FFFFFFFF)
            */

            if (FUKU_GET_CHANCE(50.f)) {
                l_res = f_asm.add(reg, fuku_immediate86(0xFFFFFFFF));
            }
            else {
                l_res = f_asm.sub(reg, fuku_immediate86(1));
            }

            l_res.set_useless_flags(target_line.get_useless_flags());

            out_lines.push_back(l_res);

            return true;
        }

        return false;
    }

    return false;
}
bool fuku_mutation_x86::fukutate_test(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];
    const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

    if (code[0] == 0x85 && (code[1] >= 0xC0 && code[1] < 0xC8)) { //test reg1,reg2
        fuku_reg86 reg1 = fuku_reg86((code[1] - 0xC0) % 8);
        fuku_reg86 reg2 = fuku_reg86((code[1] - 0xC0) / 8);

        if (reg1 == fuku_reg86::r_ESP) {
            fuku_reg86 reg3;
            for (reg3 = fuku_reg86::r_EAX; reg3 < fuku_reg86::r_EBX; reg3 = fuku_reg86(reg3 + 1)) {}

            out_lines.push_back(f_asm.push(reg3).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.mov(reg3, reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.lea(reg3, fuku_operand86(reg3, operand_scale::operand_scale_1, 4)).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.and_(reg3, reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg3));

            /*
            push reg3
            mov reg3,reg1
            lea reg3, [reg3 + 4]
            and reg3,reg2
            pop reg3
            */
        }
        else {
            out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.and_(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg1));
            /*
            push reg1
            and reg1,reg2
            pop reg1
            */
        }

        return true;
    }
    else if (code[0] == 0xA9 || (code[0] == 0xF7 && code[1] >= 0xC0 && code[1] < 0xC8)) { //test reg, imm
        fuku_reg86 reg1;
        uint32_t val;
        if (code[0] == 0xA9) {
            reg1 = fuku_reg86::r_EAX;
            val = *(uint32_t*)&code[1];
        }
        else {
            reg1 = fuku_reg86(code[1] - 0xC0);
            val = *(uint32_t*)&code[2];
        }

        if (reg1 == fuku_reg86::r_ESP) {
            fuku_reg86 reg2;
            for (reg2 = fuku_reg86::r_EAX; reg2 < fuku_reg86::r_EBX; reg2 = fuku_reg86(reg2 + 1)) {}

            out_lines.push_back(f_asm.push(reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.mov(reg2, reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.lea(reg2, fuku_operand86(reg2, operand_scale::operand_scale_1, 4)).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.and_(reg2, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg2));

            /*
            push reg2
            mov reg2,reg1
            lea reg2, [reg2 + 4]
            sub reg2,imm
            pop reg3
            */
        }
        else {
            out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.and_(reg1, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg1));

            /*
            push reg
            and reg, imm
            pop reg
            */
        }
        return true;
    }



    return false;
}
bool fuku_mutation_x86::fukutate_cmp(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];
    const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

    if ( (code[0] == 0x39 || code[0] == 0x3B) && (code[1] >= 0xC0 && code[1] < 0xC8)) { //cmp reg1,reg2
        fuku_reg86 reg1 = fuku_reg86((code[1] - 0xC0) % 8);
        fuku_reg86 reg2 = fuku_reg86((code[1] - 0xC0) / 8);

        if (code[0] == 0x3B) {
            std::swap(reg1, reg2);
        }


        if (reg1 == fuku_reg86::r_ESP) {
            fuku_reg86 reg3;
            for (reg3 = fuku_reg86::r_EAX; reg3 < fuku_reg86::r_EBX; reg3 = fuku_reg86(reg3 + 1)) {}


            out_lines.push_back(f_asm.push(reg3).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.mov(reg3,reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.lea(reg3, fuku_operand86(reg3,operand_scale::operand_scale_1,4)).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.sub(reg3, reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg3));

            /*
            push reg3
            mov reg3,reg1
            lea reg3, [reg3 + 4]
            sub reg3,reg2
            pop reg3
            */
        }
        else {
            out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.sub(reg1, reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg1));

            /*
            push reg1
            sub reg1,reg2
            pop reg1
            */
        }
        
        return true;
    }
    else if (code[0] == 0x39 || (code[0] == 0x81 && code[1] >= 0xF8)) { //cmp reg, imm
        fuku_reg86 reg1;
        uint32_t val;
        if (code[0] == 0x39) {
            reg1 = fuku_reg86::r_EAX;
            val = *(uint32_t*)&code[1];
        }
        else {
            reg1 = fuku_reg86(code[1] - 0xF8);
            val = *(uint32_t*)&code[2];
        }

        if (reg1 == fuku_reg86::r_ESP) {
            fuku_reg86 reg2;
            for (reg2 = fuku_reg86::r_EAX; reg2 < fuku_reg86::r_EBX; reg2 = fuku_reg86(reg2 + 1)) {}

            out_lines.push_back(f_asm.push(reg2).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.mov(reg2, reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.lea(reg2, fuku_operand86(reg2, operand_scale::operand_scale_1, 4)).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.sub(reg2, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg2));

            /*
            push reg2
            mov reg2,reg1
            lea reg2, [reg2 + 4]
            sub reg2,imm
            pop reg3
            */
        }
        else {
            out_lines.push_back(f_asm.push(reg1).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.sub(reg1, fuku_immediate86(val)).set_useless_flags(target_line.get_useless_flags()));
            out_lines.push_back(f_asm.pop(reg1));

            /*
            push reg
            sub reg, imm
            pop reg
            */
        }


        return true;
    }

    return false;
}
bool fuku_mutation_x86::fukutate_jcc(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];

    if (ISNT_LAST) {
        const uint8_t* code = &target_line.get_op_code()[target_line.get_op_pref_size()];

        fuku_instruction l_jmp = f_asm.jmp(0);
        l_jmp.set_ip_relocation_destination(target_line.get_ip_relocation_destination());
        l_jmp.set_link_label_id(target_line.get_link_label_id());

        uint8_t cond;

        if (code[0] == 0x0F) {
            cond = code[1] & 0xF;
        }
        else {
            cond = code[0] & 0xF;
        }

        fuku_instruction l_jcc = f_asm.jcc(fuku_condition(cond^1),0);
        l_jcc.set_link_label_id(obfuscator->set_label(lines[current_line_idx+1]));


        out_lines.push_back(l_jcc);
        out_lines.push_back(l_jmp);
        return true;
    }


    return false;
}

bool fuku_mutation_x86::fukutate_jmp(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {
    return false;
    auto& target_line = lines[current_line_idx];

    if (target_line.get_op_code()[0] == 0xE9) {

        fuku_instruction l_push = f_asm.push_imm32(0); //push 00000000
        l_push.set_flags(ob_fuku_instruction_has_relocation);

        l_push.set_relocation_f_imm_offset(1);
        l_push.set_relocation_f_id(0);

        if (target_line.get_link_label_id()) { //internal jmp
            l_push.set_relocation_f_label_id(target_line.get_link_label_id());
        }
        else { //external jmp
            l_push.set_relocation_f_destination(target_line.get_ip_relocation_destination());
        }

        out_lines.push_back(l_push);
        out_lines.push_back(f_asm.ret(0));//ret
        return true;
    }

    return false;
}
bool fuku_mutation_x86::fukutate_ret(std::vector<fuku_instruction>& lines, unsigned int current_line_idx, std::vector<fuku_instruction>& out_lines) {

    auto& target_line = lines[current_line_idx];

    if (target_line.get_op_code()[0] == 0xC3) { //ret

        out_lines.push_back(f_asm.lea(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP,4)));//lea esp,[esp + (4 + stack_offset)]
        out_lines.push_back(f_asm.jmp(fuku_operand86(r_ESP,-4)));           //jmp [esp - (4 + stack_offset)] 

        return true;

    } else if (target_line.get_op_code()[0] == 0xC2) { //ret 0x0000
        uint16_t ret_stack = *(uint16_t*)target_line.get_op_code()[1];
        out_lines.push_back(f_asm.add(fuku_reg86::r_ESP, fuku_operand86(fuku_reg86::r_ESP,4 + ret_stack)));//lea esp,[esp + (4 + stack_offset)]
        out_lines.push_back(f_asm.jmp(fuku_operand86(r_ESP, - 4 - ret_stack)));          //jmp [esp - (4 + stack_offset)] 
        
        return true;
    }

    return false;
}

void fuku_mutation_x86::fuku_junk(std::vector<fuku_instruction>& lines, unsigned int current_line_idx,
    std::vector<fuku_instruction>& out_lines) {



}


void fuku_mutation_x86::fuku_junk_1b(std::vector<fuku_instruction>& out_lines) {
    out_lines.push_back(f_asm.nop());
}

void fuku_mutation_x86::fuku_junk_2b(std::vector<fuku_instruction>& out_lines) {
    
    switch (FUKU_GET_RAND(0,2)) {
    
    case 0: {
        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
        out_lines.push_back(f_asm.mov(reg1,reg1));        
        break;
    }
    case 1: {
        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
        fuku_reg86 reg2 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
        
        if (FUKU_GET_RAND(0, 1)) {
            out_lines.push_back(f_asm.xchg(reg1, reg2));
        }
        else {
            out_lines.push_back(f_asm.xchg(reg2, reg1));
        }

        if (FUKU_GET_RAND(0, 1)) {
            out_lines.push_back(f_asm.xchg(reg1, reg2));
        }
        else {
            out_lines.push_back(f_asm.xchg(reg2, reg1));
        }
        break;
    }
    case 2: {
        fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
        out_lines.push_back(f_asm.push(reg1));
        out_lines.push_back(f_asm.pop(reg1));
    }
    }
}

void fuku_mutation_x86::fuku_junk_4b(std::vector<fuku_instruction>& out_lines) {

    fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
    out_lines.push_back(f_asm.not_(reg1));
    out_lines.push_back(f_asm.not_(reg1));

}

void fuku_mutation_x86::fuku_junk_7b(std::vector<fuku_instruction>& out_lines) {
    fuku_reg86 reg1 = fuku_reg86(FUKU_GET_RAND(fuku_reg86::r_EAX, fuku_reg86::r_EBX));
    out_lines.push_back(f_asm.push(reg1));
    out_lines.push_back(f_asm.mov(reg1,fuku_immediate86(FUKU_GET_RAND(0, 0xFFFFFFFF))));
    out_lines.push_back(f_asm.pop(reg1));
}
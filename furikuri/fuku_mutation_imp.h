#pragma once

struct mutation_context {
    fuku_assambler* f_asm;
    fuku_code_holder* code_holder;
    fuku_settings_obfuscation* settings;

    cs_insn* instruction; //current instruction desc

    inststorage::iterator prev_inst_iter; //previus inst iter
    inststorage::iterator original_inst_iter; //current insts row iter 
    inststorage::iterator payload_inst_iter;  //current insts "payload" iter
    inststorage::iterator next_inst_iter; //next inst iter

    fuku_code_label* original_start_label;
    fuku_code_label* payload_start_label;

    bool is_first_inst; //is inst iter on begin
    bool is_next_last_inst; //is next inst iter on end
    bool has_source_address; //is inst has source address

    uint32_t inst_flags;
    uint64_t cpu_flags;
    uint64_t cpu_registers;
    uint64_t source_address;

    void initialize_context(inststorage::iterator& iter) {
        this->is_first_inst = iter == this->code_holder->get_insts().begin();
        

        this->prev_inst_iter = iter;
        if (!this->is_first_inst) { --this->prev_inst_iter; }
        this->original_inst_iter = iter;
        this->payload_inst_iter = iter;
        this->next_inst_iter = iter;
        ++this->next_inst_iter;

        this->is_next_last_inst = this->next_inst_iter == this->code_holder->get_insts().end();

        this->original_start_label = iter->get_label();
        this->payload_start_label = 0;

        this->cpu_flags = iter->get_cpu_flags();
        this->cpu_registers = iter->get_cpu_registers();
        this->inst_flags = iter->get_inst_flags();
        this->has_source_address = iter->has_source_address();

        if (this->has_source_address) {
            this->source_address = iter->get_source_address();
        }
    }

    fuku_code_label* generate_payload_label() {

        if (!payload_start_label) {
            payload_start_label = code_holder->create_label(fuku_code_label());
        }

        return payload_start_label;
    }

    inststorage::iterator calc_original_inst_iter() {

        if (this->is_first_inst) {
            return this->code_holder->get_insts().begin();
        }
        else {
            inststorage::iterator iter = this->prev_inst_iter;
            return ++iter;
        }
    }

    void update_payload_inst_iter() {
        this->payload_inst_iter = calc_next_inst_iter();
        --this->payload_inst_iter;
    }

    inststorage::iterator calc_next_inst_iter() {

        return this->next_inst_iter;
    }
};

typedef bool (*_fukutate_instruction)(mutation_context& ctx);

class fuku_mutation {
public:
    virtual ~fuku_mutation() {};

    virtual void obfuscate(fuku_code_holder& code_holder) {};
    virtual void generate_junk(std::vector<uint8_t>& junk, size_t junk_size) {};
};


#include "fuku_mutation_x86.h"
#include "fuku_mutation_x64.h"


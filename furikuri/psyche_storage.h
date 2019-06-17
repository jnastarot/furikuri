#pragma once

class psyche_cmd_arg;
class psyche_cmd;
class psyche_block;
class psyche_handler_sign;
class psyche_handler;

typedef std::list<psyche_block> blocks_table;
typedef std::list<psyche_cmd> commands_table;
typedef std::map<fuku_instruction*, commands_table> psy_instructions;
typedef std::map<uint32_t, std::vector<uint32_t>> psy_block_props;

#include "psyche_handler.h"
#include "psyche_pcode.h"
#include "psyche_cmd.h"
#include "psyche_block.h"

class psyche_storage {
    shibari_module* target_module;
    fuku_code_holder* code_holder;
    
    blocks_table blocks;
    psyche_handler_manager handler_manager;
    psyche_pcode_manager pcode_manager;

    fuku_code_holder vm;
    
public:
    psyche_storage();
    psyche_storage(shibari_module* target_module, fuku_code_holder* code_holder);
    ~psyche_storage();


public:
    void set_target_module(shibari_module* module_);
    void set_code_holder(fuku_code_holder* holder);
    void set_psy_blocks(const blocks_table& blocks);

public:

    const shibari_module* get_target_module() const;
    shibari_module* get_target_module();

    const fuku_code_holder* get_code_holder() const;
    fuku_code_holder* get_code_holder();

    const blocks_table& get_blocks_table() const;
    blocks_table& get_blocks_table();

    const psyche_pcode_manager& get_pcode_manager() const;
    psyche_pcode_manager& get_pcode_manager();

    const psyche_handler_manager& get_handler_manager() const;
    psyche_handler_manager& get_handler_manager();

    const fuku_code_holder& get_vm() const;
    fuku_code_holder& get_vm();
};


/*


        block_1->|
                 |
                 |instr1  ->| command_op1(arg1)               
                 |
                 |instr2  ->| command_op2(arg1,arg2)
                 |          | command_op3(arg1)
                 ...

        block_2->|
                 |
                 |instr1  ->| command_op6(arg1)
                 ...
        ...



*/
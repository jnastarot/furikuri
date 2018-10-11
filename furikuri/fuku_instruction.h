#pragma once

enum fuku_instuction_flags {
    fuku_instruction_has_relocation_1     = 1 << 1,
    fuku_instruction_has_relocation_2     = 1 << 2,
    fuku_instruction_has_rip_relocation   = 1 << 2,

    fuku_instruction_bad_stack         = 1 << 30,
    fuku_instruction_full_mutated      = 1 << 31,
};



class fuku_instruction {
    uint16_t id; //instruction id

    uint8_t op_length;    //instruction size
    uint8_t	op_code[16];  //instruction
    
    //association
    uint64_t source_virtual_address;    //original va of instruction , == -1 if wasnt in original code
    uint64_t virtual_address;		    //resulted va of instruction

    //relative idxs    if has index then value => 0 else -1
    size_t label_idx;

    size_t code_relocation_1_idx;
    size_t code_relocation_2_idx;
    size_t code_rip_relocation_idx;
			   
    uint32_t instruction_flags; //combination of or fuku_instuction_flags

    uint64_t eflags;
    uint64_t custom_flags;

    uint8_t fuku_instruction::get_prefixes_number() const;
public:
    fuku_instruction::fuku_instruction();
    fuku_instruction::fuku_instruction(const fuku_instruction& line);
    fuku_instruction::~fuku_instruction();

    fuku_instruction& fuku_instruction::operator=(const fuku_instruction& line);
public:
    fuku_instruction & fuku_instruction::set_id(uint16_t id);

    fuku_instruction&  fuku_instruction::set_op_code(const uint8_t* op_code, uint8_t lenght);

    fuku_instruction&  fuku_instruction::set_source_virtual_address(uint64_t va);
    fuku_instruction&  fuku_instruction::set_virtual_address(uint64_t va);

    fuku_instruction&  fuku_instruction::set_label_idx(size_t idx);

    fuku_instruction&  fuku_instruction::set_relocation_first_idx(size_t idx);
    fuku_instruction&  fuku_instruction::set_relocation_second_idx(size_t idx);
    
    fuku_instruction&  fuku_instruction::set_rip_relocation_idx(size_t idx);

    fuku_instruction&  fuku_instruction::set_instruction_flags(uint32_t instruction_flags);
    
    fuku_instruction&  fuku_instruction::set_eflags(uint64_t eflags);
    fuku_instruction&  fuku_instruction::set_custom_flags(uint64_t custom_flags);
public:
    uint16_t fuku_instruction::get_id() const;

    const uint8_t* fuku_instruction::get_op_code() const;
    uint8_t  fuku_instruction::get_op_length() const;
    uint8_t  fuku_instruction::get_op_pref_size() const;

    uint64_t fuku_instruction::get_source_virtual_address() const;
    uint64_t fuku_instruction::get_virtual_address() const;
    
    size_t fuku_instruction::get_label_idx() const;

    size_t fuku_instruction::get_relocation_first_idx() const;
    size_t fuku_instruction::get_relocation_second_idx() const;

    size_t fuku_instruction::get_rip_relocation_idx() const;

    uint32_t fuku_instruction::get_instruction_flags() const;
    uint64_t fuku_instruction::get_eflags() const;
    uint64_t fuku_instruction::get_custom_flags() const;
};

typedef std::list<fuku_instruction> linestorage;
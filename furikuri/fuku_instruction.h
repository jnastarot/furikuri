#pragma once

enum ob_fuku_flags {
    ob_fuku_instruction_has_relocation    = 1 << 1,
    ob_fuku_instruction_has_ip_relocation = 1 << 2,
};



class fuku_instruction {
    uint8_t	op_code[16];
    uint8_t op_length;
    uint8_t op_pref_size;

    //association
    uint64_t source_virtual_address;    //original va of instruction , == -1 if wasnt in original code
    uint64_t virtual_address;		    //resulted va of instruction			   

    //ip_relocation
    uint64_t ip_relocation_destination; //destination address va where references         
    uint8_t	 ip_relocation_disp_offset; //offset to reloc disp (e\r)ip relative

    //relocations
    uint32_t relocation_f_id;	            //set if has reloc from initialize reloc table					
    uint8_t	 relocation_f_imm_offset;       //offset to reloc imm
    uint64_t relocation_f_destination;      //destination address va where references         

    uint32_t relocation_s_id;	            //set if has reloc from initialize reloc table					
    uint8_t	 relocation_s_imm_offset;       //offset to reloc imm
    uint64_t relocation_s_destination;      //destination address va where references         


    //labels
    uint32_t label_id;			    // != 0 if has own label
    uint32_t link_label_id;         // != 0 if has link label
    uint32_t relocation_f_label_id;   // != 0 if has label on destination instruction in array
    uint32_t relocation_s_label_id;   // != 0 if has label on destination instruction in array

    uint32_t flags; //ob_fuku_flags

    uint16_t type;
    uint16_t modified_flags;
    uint16_t tested_flags;

    uint8_t fuku_instruction::get_prefixes_number();
public:
    fuku_instruction::fuku_instruction();
    fuku_instruction::fuku_instruction(const fuku_instruction& line);
    fuku_instruction::~fuku_instruction();

    fuku_instruction& fuku_instruction::operator=(const fuku_instruction& line);
public:
    fuku_instruction&  fuku_instruction::set_op_code(uint8_t* op_code, uint8_t lenght);

    fuku_instruction&  fuku_instruction::set_source_virtual_address(uint64_t va);
    fuku_instruction&  fuku_instruction::set_virtual_address(uint64_t va);

    fuku_instruction&  fuku_instruction::set_ip_relocation_destination(uint64_t dst_va);
    fuku_instruction&  fuku_instruction::set_ip_relocation_disp_offset(uint8_t offset);

    fuku_instruction&  fuku_instruction::set_relocation_f_id(uint32_t id);
    fuku_instruction&  fuku_instruction::set_relocation_f_imm_offset(uint8_t offset);
    fuku_instruction&  fuku_instruction::set_relocation_f_destination(uint64_t dst);
    fuku_instruction&  fuku_instruction::set_relocation_s_id(uint32_t id);
    fuku_instruction&  fuku_instruction::set_relocation_s_imm_offset(uint8_t offset);
    fuku_instruction&  fuku_instruction::set_relocation_s_destination(uint64_t dst);

    fuku_instruction&  fuku_instruction::set_label_id(uint32_t id);
    fuku_instruction&  fuku_instruction::set_link_label_id(uint32_t id);
    fuku_instruction&  fuku_instruction::set_relocation_f_label_id(uint32_t id);
    fuku_instruction&  fuku_instruction::set_relocation_s_label_id(uint32_t id);

    fuku_instruction&  fuku_instruction::set_flags(uint32_t flags);

    fuku_instruction&  fuku_instruction::set_type(uint16_t type);
    fuku_instruction&  fuku_instruction::set_modified_flags(uint16_t modified_flags);
    fuku_instruction&  fuku_instruction::set_tested_flags(uint16_t tested_flags);
public:
    const uint8_t* fuku_instruction::get_op_code() const;
    uint8_t  fuku_instruction::get_op_length() const;
    uint8_t  fuku_instruction::get_op_pref_size() const;

    uint64_t fuku_instruction::get_source_virtual_address() const;
    uint64_t fuku_instruction::get_virtual_address() const;

    uint64_t fuku_instruction::get_ip_relocation_destination() const;
    uint8_t	 fuku_instruction::get_ip_relocation_disp_offset() const;

    uint32_t fuku_instruction::get_relocation_f_id() const;
    uint8_t	 fuku_instruction::get_relocation_f_imm_offset() const;
    uint64_t fuku_instruction::get_relocation_f_destination() const;
    uint32_t fuku_instruction::get_relocation_s_id() const;
    uint8_t	 fuku_instruction::get_relocation_s_imm_offset() const;
    uint64_t fuku_instruction::get_relocation_s_destination() const;

    uint32_t fuku_instruction::get_label_id() const;
    uint32_t fuku_instruction::get_link_label_id() const;
    uint32_t fuku_instruction::get_relocation_f_label_id() const;
    uint32_t fuku_instruction::get_relocation_s_label_id() const;

    uint32_t fuku_instruction::get_flags() const;

    uint16_t fuku_instruction::get_type() const;
    uint16_t fuku_instruction::get_modified_flags() const;
    uint16_t fuku_instruction::get_tested_flags() const;
public:
    void fuku_instruction::set_jump_imm(uint64_t destination_virtual_address);

    bool    fuku_instruction::is_jump() const;
    int32_t fuku_instruction::get_jump_imm() const;
};


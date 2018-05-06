#pragma once

enum obfkstruction_flags {
    obfkst_instruction_has_relocation    = 1 << 1,
    obfkst_instruction_has_ip_relocation = 1 << 2,
};


class obfurikuristruction{
    uint8_t	op_code[16];
    uint8_t op_length;
    uint8_t op_pref_size;

    //association
    uint64_t source_virtual_address;    //in va of instruction
    uint64_t virtual_address;		    //resulted va of instruction			   

    //ip_relocation
    uint64_t ip_relocation_destination; //destination address va where references         
    uint8_t	 ip_relocation_disp_offset; //offset to reloc disp (e\r)ip relative

    //relocations
    uint32_t relocation_id;	            //set if has reloc from initialize reloc table					
    uint8_t	 relocation_imm_offset;     //offset to reloc imm
    
    //labels
    uint32_t label_id;			    // != 0 if has own label
    uint32_t link_label_id;         // != 0 if has link label
    uint32_t relocation_label_id;   // != 0 if has label on destination instruction in array


    uint32_t flags; //obfkstruction_flags

    uint8_t obfurikuristruction::get_prefixes_number();
public:
    obfurikuristruction::obfurikuristruction();
    obfurikuristruction::~obfurikuristruction();

public:
    void  obfurikuristruction::set_op_code(uint8_t* op_code, uint8_t lenght);

    void  obfurikuristruction::set_source_virtual_address(uint64_t va);
    void  obfurikuristruction::set_virtual_address(uint64_t va);

    void  obfurikuristruction::set_ip_relocation_destination(uint64_t dst_va);
    void  obfurikuristruction::set_ip_relocation_disp_offset(uint8_t offset);

    void  obfurikuristruction::set_relocation_id(uint32_t id);
    void  obfurikuristruction::set_relocation_imm_offset(uint8_t offset);

    void  obfurikuristruction::set_label_id(uint32_t id);
    void  obfurikuristruction::set_link_label_id(uint32_t id);
    void  obfurikuristruction::set_relocation_label_id(uint32_t id);
     
    void  obfurikuristruction::set_flags(uint32_t flags);
public:
    const uint8_t* obfurikuristruction::get_op_code() const;
    uint8_t  obfurikuristruction::get_op_length() const;
    uint8_t  obfurikuristruction::get_op_pref_size() const;

    uint64_t obfurikuristruction::get_source_virtual_address() const;
    uint64_t obfurikuristruction::get_virtual_address() const;

    uint64_t obfurikuristruction::get_ip_relocation_destination() const;
    uint8_t	 obfurikuristruction::get_ip_relocation_disp_offset() const;

    uint32_t obfurikuristruction::get_relocation_id() const;
    uint8_t	 obfurikuristruction::get_relocation_imm_offset() const;

    uint32_t obfurikuristruction::get_label_id() const;
    uint32_t obfurikuristruction::get_link_label_id() const;
    uint32_t obfurikuristruction::get_relocation_label_id() const;

    uint32_t obfurikuristruction::get_flags() const;

public:
    void obfurikuristruction::set_jump_imm(uint64_t destination_virtual_address);

    bool    obfurikuristruction::is_jump() const;
    int32_t obfurikuristruction::get_jump_imm() const;
};


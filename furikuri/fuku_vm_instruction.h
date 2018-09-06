#pragma once

class fuku_vm_instruction {
    std::vector<uint8_t> pcode;

    uint64_t source_virtual_address;
    uint64_t virtual_address;

    uint32_t label_id;			    // != 0 if has own label
    uint32_t link_label_id;         // != 0 if has link label

    uint16_t type;

    fuku_instruction * original;

    void * custom_data;
public:
    fuku_vm_instruction::fuku_vm_instruction();
    fuku_vm_instruction::fuku_vm_instruction(uint16_t type);
    fuku_vm_instruction::fuku_vm_instruction(uint16_t type, std::vector<uint8_t>& pcode);
    fuku_vm_instruction::fuku_vm_instruction(const fuku_vm_instruction& _pcode);
    fuku_vm_instruction::~fuku_vm_instruction();

    fuku_vm_instruction& operator=(const fuku_vm_instruction& _pcode);
public:
    void  set_source_virtual_address(uint64_t source_virtual_address);
    void  set_virtual_address(uint64_t virtual_address);
    void  set_label_id(uint32_t label_id);
    void  set_link_label_id(uint32_t link_label_id);
    void  set_type(uint16_t type);
    void  set_original(fuku_instruction * line);
    void  set_custom_data(void * custom_data);
    void  set_pcode(const std::vector<uint8_t>& _pcode);

    void  add_pcode(uint8_t code);
    void  add_pcode(uint16_t code);
    void  add_pcode(uint32_t code);
    void  add_pcode(uint64_t code);

    
public:
    uint64_t  get_source_virtual_address() const;
    uint64_t  get_virtual_address() const;
    uint32_t  get_label_id() const;			    
    uint32_t  get_link_label_id() const;        
    uint16_t  get_type() const;
    fuku_instruction * get_original() const;

    void *    get_custom_data() const;

    std::vector<uint8_t>& get_pcode();
    const std::vector<uint8_t>& get_pcode() const;
};

typedef std::vector<fuku_vm_instruction> vm_linestorage;
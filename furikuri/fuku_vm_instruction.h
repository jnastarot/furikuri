#pragma once

class fuku_vm_instruction {
    std::vector<uint8_t> pcode;

    uint64_t source_virtual_address;//original va of instruction , == -1 if wasnt in original code

    uint32_t label_id;			    // != 0 if has own label
    uint32_t link_label_id;         // != 0 if has link label


public:
    fuku_vm_instruction::fuku_vm_instruction();
    fuku_vm_instruction::fuku_vm_instruction(const fuku_vm_instruction& _pcode);
    fuku_vm_instruction::~fuku_vm_instruction();

    fuku_vm_instruction& operator=(const fuku_vm_instruction& _pcode);
public:
    void  set_source_virtual_address(uint64_t source_virtual_address);
    void  set_label_id(uint32_t label_id);
    void  set_link_label_id(uint32_t link_label_id);

    void  set_pcode(const std::vector<uint8_t>& _pcode);
public:
    uint64_t  get_source_virtual_address() const;
    uint32_t  get_label_id() const;			    
    uint32_t  get_link_label_id() const;        

    std::vector<uint8_t>& get_pcode();
    const std::vector<uint8_t>& get_pcode() const;
};


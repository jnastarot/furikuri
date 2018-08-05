#include "stdafx.h"
#include "fuku_vm_instruction.h"


fuku_vm_instruction::fuku_vm_instruction()
:source_virtual_address(0), label_id(0), link_label_id(0){
}

fuku_vm_instruction::fuku_vm_instruction(const fuku_vm_instruction& _pcode) {
    operator=(_pcode);
}

fuku_vm_instruction::~fuku_vm_instruction()
{
}

fuku_vm_instruction& fuku_vm_instruction::operator=(const fuku_vm_instruction& _pcode) {

    this->pcode = _pcode.pcode;
    this->source_virtual_address = _pcode.source_virtual_address;
    this->label_id      = _pcode.label_id;
    this->link_label_id = _pcode.link_label_id;

    return *this;
}

void  fuku_vm_instruction::set_source_virtual_address(uint64_t source_virtual_address) {
    this->source_virtual_address = source_virtual_address;
}

void  fuku_vm_instruction::set_label_id(uint32_t label_id) {
    this->label_id = label_id;
}

void  fuku_vm_instruction::set_link_label_id(uint32_t link_label_id) {
    this->link_label_id = link_label_id;
}

void fuku_vm_instruction::set_pcode(const std::vector<uint8_t>& _pcode) {
    this->pcode = _pcode;
}
    
uint64_t  fuku_vm_instruction::get_source_virtual_address() const {
    return this->source_virtual_address;
}

uint32_t  fuku_vm_instruction::get_label_id() const {
    return this->label_id;
}

uint32_t  fuku_vm_instruction::get_link_label_id() const {
    return this->link_label_id;
}

std::vector<uint8_t>& fuku_vm_instruction::get_pcode() {
    return this->pcode;
}

const std::vector<uint8_t>& fuku_vm_instruction::get_pcode() const {
    return this->pcode;
}
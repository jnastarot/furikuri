#include "stdafx.h"
#include "fuku_vm_instruction.h"


fuku_vm_instruction::fuku_vm_instruction()
    : source_virtual_address(0), virtual_address(0), label_id(0), link_label_id(0), type(0){}

fuku_vm_instruction::fuku_vm_instruction(uint16_t type) 
    : source_virtual_address(0), virtual_address(0), label_id(0), link_label_id(0), type(type) {}

fuku_vm_instruction::fuku_vm_instruction(uint16_t type, std::vector<uint8_t>& pcode) 
    : source_virtual_address(0), virtual_address(0), label_id(0), link_label_id(0), type(type), pcode(pcode){}

fuku_vm_instruction::fuku_vm_instruction(const fuku_vm_instruction& _pcode) {
    operator=(_pcode);
}

fuku_vm_instruction::~fuku_vm_instruction()
{
}

fuku_vm_instruction& fuku_vm_instruction::operator=(const fuku_vm_instruction& _pcode) {

    this->pcode = _pcode.pcode;
    this->source_virtual_address = _pcode.source_virtual_address;
    this->virtual_address = _pcode.virtual_address;
    this->label_id      = _pcode.label_id;
    this->link_label_id = _pcode.link_label_id;
    this->type = _pcode.type;
    return *this;
}

void  fuku_vm_instruction::set_source_virtual_address(uint64_t source_virtual_address) {
    this->source_virtual_address = source_virtual_address;
}

void  fuku_vm_instruction::set_virtual_address(uint64_t virtual_address) {
    this->virtual_address = virtual_address;
}

void  fuku_vm_instruction::set_label_id(uint32_t label_id) {
    this->label_id = label_id;
}

void  fuku_vm_instruction::set_link_label_id(uint32_t link_label_id) {
    this->link_label_id = link_label_id;
}

void  fuku_vm_instruction::set_type(uint16_t type) {
    this->type = type;
}

void fuku_vm_instruction::set_pcode(const std::vector<uint8_t>& _pcode) {
    this->pcode = _pcode;
}
    
void  fuku_vm_instruction::add_pcode(uint8_t code) {
    this->pcode.push_back(code);
}
void  fuku_vm_instruction::add_pcode(uint16_t code){
    this->pcode.push_back(((uint8_t*)&code)[0]);
    this->pcode.push_back(((uint8_t*)&code)[1]);
}
void  fuku_vm_instruction::add_pcode(uint32_t code) {
    this->pcode.push_back(((uint8_t*)&code)[0]);
    this->pcode.push_back(((uint8_t*)&code)[1]);
    this->pcode.push_back(((uint8_t*)&code)[2]);
    this->pcode.push_back(((uint8_t*)&code)[3]);
}
void  fuku_vm_instruction::add_pcode(uint64_t code) {
    this->pcode.push_back(((uint8_t*)&code)[0]);
    this->pcode.push_back(((uint8_t*)&code)[1]);
    this->pcode.push_back(((uint8_t*)&code)[2]);
    this->pcode.push_back(((uint8_t*)&code)[3]);
    this->pcode.push_back(((uint8_t*)&code)[4]);
    this->pcode.push_back(((uint8_t*)&code)[5]);
    this->pcode.push_back(((uint8_t*)&code)[6]);
    this->pcode.push_back(((uint8_t*)&code)[7]);
}

uint64_t  fuku_vm_instruction::get_source_virtual_address() const {
    return this->source_virtual_address;
}

uint64_t  fuku_vm_instruction::get_virtual_address() const {
    return this->virtual_address;
}

uint32_t  fuku_vm_instruction::get_label_id() const {
    return this->label_id;
}

uint32_t  fuku_vm_instruction::get_link_label_id() const {
    return this->link_label_id;
}

uint16_t  fuku_vm_instruction::get_type() const {
    return this->type;
}

std::vector<uint8_t>& fuku_vm_instruction::get_pcode() {
    return this->pcode;
}

const std::vector<uint8_t>& fuku_vm_instruction::get_pcode() const {
    return this->pcode;
}
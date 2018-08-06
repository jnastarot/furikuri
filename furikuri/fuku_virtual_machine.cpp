#include "stdafx.h"
#include "fuku_virtual_machine.h"


fuku_virtual_machine::fuku_virtual_machine()
{
}


fuku_virtual_machine::~fuku_virtual_machine()
{
}


void fuku_virtual_machine::set_code(const fuku_code_analyzer& code) {
    this->arch = code.get_arch();
    this->lines = code.get_lines();
    this->label_seed = code.get_label_seed();
}

void fuku_virtual_machine::set_destination_virtual_address(uint64_t destination_virtual_address) {
    this->destination_virtual_address = destination_virtual_address;
}

void fuku_virtual_machine::set_settings(const fuku_vm_settings& settings) {

}

void fuku_virtual_machine::set_association_table(std::vector<fuku_code_association>*	associations){

}

fuku_arch           fuku_virtual_machine::get_arch() const {
    return this->arch;
}

const std::vector<fuku_instruction>& fuku_virtual_machine::get_lines() const {
    return this->lines;
}

uint64_t            fuku_virtual_machine::get_destination_virtual_address() const {
    return this->destination_virtual_address;
}

fuku_vm_settings    fuku_virtual_machine::get_settings() const {
   
}

std::vector<fuku_code_association>*    fuku_virtual_machine::get_association_table() {
   
}

std::vector<fuku_code_relocation>*     fuku_virtual_machine::get_relocation_table() {

}
#include "stdafx.h"
#include "fuku_virtual_machine.h"


fuku_virtual_machine::fuku_virtual_machine(){}


fuku_virtual_machine::~fuku_virtual_machine(){}


fuku_vm_result fuku_virtual_machine::build_bytecode(std::vector<uint8_t>& bytecode) {
    bytecode.clear();

    return fuku_vm_result::fuku_vm_ok;
}


void fuku_virtual_machine::set_code(const fuku_code_analyzer& code) {
    this->code = code;
}

void fuku_virtual_machine::set_code(const fuku_analyzed_code& code) {
    this->code = code;
}

void fuku_virtual_machine::set_destination_virtual_address(uint64_t destination_virtual_address) {
    this->destination_virtual_address = destination_virtual_address;
}

void fuku_virtual_machine::set_settings(const fuku_vm_settings& settings) {
    this->settings = settings;
}

void fuku_virtual_machine::set_relocation_table(std::vector<fuku_code_relocation>* relocs) {
    this->relocation_table = relocs;
}

fuku_arch           fuku_virtual_machine::get_arch() const {
    return this->code.arch;
}

const linestorage& fuku_virtual_machine::get_lines() const {
    return this->code.lines;
}

uint64_t            fuku_virtual_machine::get_destination_virtual_address() const {
    return this->destination_virtual_address;
}

fuku_vm_settings    fuku_virtual_machine::get_settings() const {
    return this->settings;
}

const std::vector<fuku_code_relocation> fuku_virtual_machine::get_relocation_table() const {
    return *relocation_table;
}

std::vector<uint8_t> fuku_virtual_machine::get_jumpout_vm(uint64_t src_address) const {
    return std::vector<uint8_t>();//todo
}
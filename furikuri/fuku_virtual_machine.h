#pragma once

enum fuku_vm_result {
    fuku_vm_ok ,
    fuku_vm_error
};

#include "fuku_virtualizer_imp.h"

class fuku_virtual_machine{
    fuku_analyzed_code code;

    uint64_t destination_virtual_address;

    fuku_vm_settings settings;

    std::vector<fuku_code_relocation>*   relocation_table;
public:
    fuku_virtual_machine::fuku_virtual_machine();
    fuku_virtual_machine::~fuku_virtual_machine();

    fuku_vm_result fuku_virtual_machine::build_bytecode(std::vector<uint8_t>& bytecode);
public:
    void fuku_virtual_machine::set_code(const fuku_code_analyzer& code);
    void fuku_virtual_machine::set_code(const fuku_analyzed_code& code);

    void fuku_virtual_machine::set_destination_virtual_address(uint64_t destination_virtual_address);
    void fuku_virtual_machine::set_settings(const fuku_vm_settings& settings);

    void fuku_virtual_machine::set_relocation_table(std::vector<fuku_code_relocation>* relocs);
public:
    fuku_arch           fuku_virtual_machine::get_arch() const;
    const linestorage& fuku_virtual_machine::get_lines() const;
    uint64_t            fuku_virtual_machine::get_destination_virtual_address() const;
    fuku_vm_settings    fuku_virtual_machine::get_settings() const;

    const std::vector<fuku_code_relocation>   fuku_virtual_machine::get_relocation_table() const;
    std::vector<uint8_t> fuku_virtual_machine::get_jumpout_vm(uint64_t src_address) const;
};


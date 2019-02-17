#pragma once

enum fuku_inst_flags {
    FUKU_INST_HAS_EXTERNAL_LABEL = 1 << 28,
    FUKU_INST_JUNK_CODE          = 1 << 29,
    FUKU_INST_BAD_STACK          = 1 << 30,
    FUKU_INST_NO_MUTATE          = 1 << 31,
};


#include "fuku_mutation_imp.h"


class fuku_obfuscator {
    fuku_code_holder *code;

    uint64_t destination_virtual_address;

    fuku_settings_obfuscation settings;

    void    fuku_obfuscator::handle_jmps();
    void    fuku_obfuscator::spagetti_code();
public:
    fuku_obfuscator::fuku_obfuscator();
    fuku_obfuscator::~fuku_obfuscator();

    void fuku_obfuscator::obfuscate_code();
public:
    void fuku_obfuscator::set_code(fuku_code_holder* code_holder);

    void fuku_obfuscator::set_destination_virtual_address(uint64_t destination_virtual_address);
    void fuku_obfuscator::set_settings(const fuku_settings_obfuscation& settings);

public:  
    fuku_assambler_arch    fuku_obfuscator::get_arch() const;
    uint64_t     fuku_obfuscator::get_destination_virtual_address() const;
    const fuku_settings_obfuscation& fuku_obfuscator::get_settings() const;

    fuku_code_holder* fuku_obfuscator::get_code();
    const fuku_code_holder* fuku_obfuscator::get_code() const;
};

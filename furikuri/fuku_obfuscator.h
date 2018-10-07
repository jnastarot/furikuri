#pragma once

#include "fuku_mutation_imp.h"

class fuku_obfuscator {
    fuku_code_holder code;

    uint64_t destination_virtual_address;

    fuku_ob_settings settings;

    void    fuku_obfuscator::handle_jmps();
    void    fuku_obfuscator::spagetti_code();
    void    fuku_obfuscator::useless_flags_profiler(); 
public:
    fuku_obfuscator::fuku_obfuscator();
    fuku_obfuscator::~fuku_obfuscator();

    void fuku_obfuscator::obfuscate_code();
public:
    void fuku_obfuscator::set_code(const fuku_code_analyzer& code_analyzer);
    void fuku_obfuscator::set_code(const fuku_code_holder& code_holder);

    void fuku_obfuscator::set_destination_virtual_address(uint64_t destination_virtual_address);
    void fuku_obfuscator::set_settings(const fuku_ob_settings& settings);

public:  
    fuku_arch    fuku_obfuscator::get_arch() const;
    uint64_t     fuku_obfuscator::get_destination_virtual_address() const;
    fuku_ob_settings fuku_obfuscator::get_settings() const;

    fuku_code_holder& fuku_obfuscator::get_code();
    const fuku_code_holder& fuku_obfuscator::get_code() const;
};

#pragma once

enum fuku_inst_flags {
    FUKU_INST_JUNK_CODE          = 1 << 0,
    FUKU_INST_BAD_STACK          = 1 << 1,
    FUKU_INST_NO_MUTATE          = 1 << 2,
};


#include "fuku_mutation_imp.h"


class fuku_obfuscator {
    fuku_code_holder *code;

    uint64_t destination_virtual_address;

    fuku_settings_obfuscation settings;

    void    handle_jmps();
    void    spagetti_code();
public:
    fuku_obfuscator();
    ~fuku_obfuscator();

    void obfuscate_code();
public:
    void set_code(fuku_code_holder* code_holder);

    void set_destination_virtual_address(uint64_t destination_virtual_address);
    void set_settings(const fuku_settings_obfuscation& settings);

public:  
    fuku_assambler_arch    get_arch() const;
    uint64_t     get_destination_virtual_address() const;
    const fuku_settings_obfuscation& get_settings() const;

    fuku_code_holder* get_code();
    const fuku_code_holder* get_code() const;
};

#pragma once

enum fuku_inst_flags {
    FUKU_INST_BAD_STACK = 1 << 30,
    FUKU_INST_NO_MUTATE = 1 << 31,
};

#define X86_EFLAGS_GROUP_TEST (X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_ZF | X86_EFLAGS_TEST_PF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_DF | X86_EFLAGS_TEST_AF)
#define X86_EFLAGS_GROUP_MODIFY (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_DF | X86_EFLAGS_MODIFY_AF)
#define X86_EFLAGS_GROUP_SET (X86_EFLAGS_SET_CF | X86_EFLAGS_SET_DF | X86_EFLAGS_SET_OF | X86_EFLAGS_SET_SF | X86_EFLAGS_SET_ZF | X86_EFLAGS_SET_AF | X86_EFLAGS_SET_PF)
#define X86_EFLAGS_GROUP_RESET (X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_CF | X86_EFLAGS_RESET_DF | X86_EFLAGS_RESET_SF | X86_EFLAGS_RESET_AF | X86_EFLAGS_RESET_ZF)
#define X86_EFLAGS_GROUP_UNDEFINED (X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_CF)


#include "fuku_mutation_imp.h"


class fuku_obfuscator {
    fuku_code_holder *code;

    uint64_t destination_virtual_address;

    fuku_settings_obfuscation settings;

    void    fuku_obfuscator::handle_jmps();
    void    fuku_obfuscator::spagetti_code();
    void    fuku_obfuscator::unused_flags_profiler();
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

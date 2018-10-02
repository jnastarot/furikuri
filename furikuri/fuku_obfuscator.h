#pragma once

#include "fuku_mutation_imp.h"

class fuku_obfuscator {
    fuku_code_holder code;

    uint64_t destination_virtual_address;

    fuku_ob_settings settings;

    std::vector<fuku_code_association>*     association_table;
    std::vector<fuku_image_relocation>*      relocation_table;

    void    fuku_obfuscator::spagetti_code(linestorage& lines, uint64_t virtual_address);
    void    fuku_obfuscator::handle_jmps(linestorage& lines);
    void    fuku_obfuscator::lines_correction(linestorage& lines, uint64_t virtual_address);
    void    fuku_obfuscator::finalize_code();
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

    void fuku_obfuscator::set_association_table(std::vector<fuku_code_association>*	associations);
    void fuku_obfuscator::set_relocation_table(std::vector<fuku_image_relocation>* relocations);
public:  
    fuku_arch    fuku_obfuscator::get_arch() const;
    uint64_t     fuku_obfuscator::get_destination_virtual_address() const;
    fuku_ob_settings fuku_obfuscator::get_settings() const;

    const std::vector<fuku_code_association>    fuku_obfuscator::get_association_table() const;
    const std::vector<fuku_image_relocation>     fuku_obfuscator::get_relocation_table() const;

    const fuku_code_holder& fuku_obfuscator::get_code() const;
};

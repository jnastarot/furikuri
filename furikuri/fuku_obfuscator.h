#pragma once
#include "fuku_mutation.h"

class fuku_obfuscator {
    fuku_arch arch;

    uint64_t destination_virtual_address;

    ob_fuku_settings settings;

    unsigned int label_seed;
    std::vector<uint32_t> labels_cache;
    std::vector<uint32_t> jumps_idx_cache;
    std::vector<uint32_t> rel_idx_cache;
    std::vector<uint32_t> ip_rel_idx_cache;

    std::vector<fuku_instruction>  lines;

    std::vector<fuku_code_association>*     association_table;
    std::vector<fuku_code_relocation>*      relocation_table;
    std::vector<fuku_code_ip_relocation>*   ip_relocation_table;

    void    fuku_obfuscator::spagetti_code(std::vector<fuku_instruction>& lines, uint64_t virtual_address);
    void    fuku_obfuscator::handle_jmps(std::vector<fuku_instruction>& lines);
    void    fuku_obfuscator::lines_correction(std::vector<fuku_instruction>& lines, uint64_t virtual_address);
    void    fuku_obfuscator::finalize_code();
    void    fuku_obfuscator::useless_flags_profiler(); 

    fuku_instruction * fuku_obfuscator::get_line_by_va(std::vector<fuku_instruction>& lines, uint64_t virtual_address);
    fuku_instruction * fuku_obfuscator::get_line_by_label_id(unsigned int label_id);
    std::vector<uint8_t>  fuku_obfuscator::lines_to_bin(std::vector<fuku_instruction>&  lines);

    uint32_t fuku_obfuscator::set_label(fuku_instruction& line);
    uint32_t fuku_obfuscator::get_maxlabel() const;
public:
    fuku_obfuscator::fuku_obfuscator();
    fuku_obfuscator::~fuku_obfuscator();

    void fuku_obfuscator::obfuscate_code();
    std::vector<uint8_t> fuku_obfuscator::get_code();
public:
    void fuku_obfuscator::set_code(const fuku_code_analyzer& code);
    void fuku_obfuscator::set_destination_virtual_address(uint64_t destination_virtual_address);
    void fuku_obfuscator::set_settings(const ob_fuku_settings& settings);

    void fuku_obfuscator::set_association_table(std::vector<fuku_code_association>*	associations);
    void fuku_obfuscator::set_relocation_table(std::vector<fuku_code_relocation>* relocations);
    void fuku_obfuscator::set_ip_relocation_table(std::vector<fuku_code_ip_relocation>* relocations); //will returned only external rip relocations
public:  
    fuku_arch    fuku_obfuscator::get_arch() const;
    const std::vector<fuku_instruction>& fuku_obfuscator::get_lines() const;
    uint64_t     fuku_obfuscator::get_destination_virtual_address() const;
    ob_fuku_settings fuku_obfuscator::get_settings() const;

    std::vector<fuku_code_association>*    fuku_obfuscator::get_association_table();
    std::vector<fuku_code_relocation>*     fuku_obfuscator::get_relocation_table();
    std::vector<fuku_code_ip_relocation>*  fuku_obfuscator::get_ip_relocation_table();
};

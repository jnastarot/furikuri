#pragma once
class fuku_protector {
    std::vector<ob_fuku_association>   assoc_table;
    std::vector<ob_fuku_relocation>    reloc_table;
    std::vector<ob_fuku_ip_relocation> ip_reloc_table;
    fuku_obfuscator obfuscator;
    
    shibari_module * module;
    fuku_code_list code_list;

    void                  fuku_protector::sort_assoc();
    ob_fuku_association * fuku_protector::find_assoc(uint32_t rva);

    void    fuku_protector::calc_zones();
    bool    fuku_protector::start_initialize_zones();
    bool    fuku_protector::finish_initialize_zones();
public:
    fuku_protector::fuku_protector(shibari_module * module, const ob_fuku_sensitivity& settings, 
        const fuku_code_list& code_list);

    fuku_protector::~fuku_protector();

public:
    bool fuku_protector::protect_module();
};


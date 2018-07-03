#pragma once

enum fuku_code_type {
    fuku_code_obfuscate,
    fuku_code_virtual,
};

struct fuku_acode {
    uint64_t region_start;
    uint64_t region_size;

    std::vector<ob_fuku_association>   association_table;
    std::vector<ob_fuku_relocation>    relocation_table;
    fuku_code_analyzer analyzer;
    fuku_code_type type;
};

class fuku_protector { 
    std::vector<fuku_acode> acodes;

    fuku_obfuscator obfuscator;
    
    shibari_module * module;
    fuku_code_list code_list;

    void                  fuku_protector::sort_assoc();
    ob_fuku_association * fuku_protector::find_assoc(uint64_t rva);

    bool    fuku_protector::start_initialize_zones();
    bool    fuku_protector::finish_initialize_zones();
public:
    fuku_protector::fuku_protector(shibari_module * module, const ob_fuku_sensitivity& settings, 
        const fuku_code_list& code_list);

    fuku_protector::~fuku_protector();

public:
    bool fuku_protector::protect_module();
};


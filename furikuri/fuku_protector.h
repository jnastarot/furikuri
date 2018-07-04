#pragma once

enum fuku_code_type {
    fuku_code_obfuscate,
    fuku_code_virtual,
};

struct fuku_protected_region {
    uint32_t region_rva;
    uint32_t region_size;
};


struct fuku_code_profile {
    std::vector<fuku_protected_region>   regions;
    std::vector<fuku_code_association>   association_table;
    std::vector<fuku_code_relocation>    relocation_table;
    std::vector<fuku_code_ip_relocation> ip_relocation_table;

    ob_fuku_sensitivity settings; //present if type == fuku_code_obfuscate

    fuku_code_analyzer analyzer;
    fuku_code_type type;
};

class fuku_protector { 
    std::vector<fuku_code_profile> profiles;

    fuku_obfuscator obfuscator;
    
    shibari_module * module;
    fuku_code_list code_list;

    void                    fuku_protector::sort_assoc();
    fuku_code_association * fuku_protector::find_assoc(uint64_t rva);

    bool    fuku_protector::start_initialize_zones();
    bool    fuku_protector::finish_initialize_zones();
public:
    fuku_protector::fuku_protector(shibari_module * module, const ob_fuku_sensitivity& settings, 
        const fuku_code_list& code_list);


    fuku_protector::~fuku_protector();



public:
    bool fuku_protector::protect_module();
};


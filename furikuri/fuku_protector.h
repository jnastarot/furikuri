#pragma once

enum fuku_protector_code {
    fuku_protector_ok,
    fuku_protector_error_code_range,
    fuku_protector_error_initialization,

};

enum fuku_code_type {
    fuku_code_obfuscate,
    fuku_code_virtual,
    fuku_code_hybrid,//obfuscation + virtualization
};

struct fuku_protected_region {
    uint32_t region_rva;
    uint32_t region_size;
};


struct fuku_code_profile {
    std::vector<fuku_protected_region>   regions;
    uint32_t out_code_rva;

    std::vector<fuku_code_association>   association_table;
    std::vector<fuku_code_relocation>    relocation_table;
    std::vector<fuku_code_ip_relocation> ip_relocation_table;

    ob_fuku_sensitivity settings;

    fuku_code_type type;

    fuku_code_analyzer analyzed_code;

    union {
        fuku_obfuscator*       obfuscator;
        fuku_virtual_machine * virtual_machine;
    }_ptr;

    fuku_code_profile::fuku_code_profile();
    fuku_code_profile::~fuku_code_profile();
};

class fuku_protector { 
    shibari_module protected_module;

    std::vector<fuku_code_profile> profiles;

    fuku_code_profile main_obfuscator, main_vm;

    
    void    fuku_protector::sort_association_tables();
    fuku_code_association * fuku_protector::find_association(fuku_code_profile& profile,uint32_t rva);
    fuku_code_association * fuku_protector::find_association(uint32_t rva);

    bool    fuku_protector::test_regions();
    bool    fuku_protector::initialize_profiles();
    void    fuku_protector::merge_profiles();
    bool    fuku_protector::finish_protected_code();
public:
    fuku_protector::fuku_protector(const shibari_module& module);
    fuku_protector::~fuku_protector();

public:
    fuku_protector_code fuku_protector::protect_module();

public:
    void fuku_protector::add_profile(const std::vector<fuku_protected_region>& regions, fuku_code_type type, const ob_fuku_sensitivity& settings = { 0 });
    void fuku_protector::clear_profiles();
public:
    const shibari_module& get_protected_module() const;
};


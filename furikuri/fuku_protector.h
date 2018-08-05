#pragma once

enum fuku_protector_code {
    fuku_protector_ok,
    fuku_protector_error_code_range,
    fuku_protector_error_initialization,
};


struct fuku_code_profile {
    std::vector<fuku_protected_region>   regions;
    std::vector<fuku_code_association>   association_table;
    std::vector<fuku_code_relocation>    relocation_table;
    std::vector<fuku_code_ip_relocation> ip_relocation_table;

    ob_fuku_settings settings;

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
    shibari_module target_module;

    std::vector<fuku_code_profile> profiles;

    fuku_code_profile main_obfuscator, main_vm;

    
    void    fuku_protector::sort_association_tables();
    fuku_code_association * fuku_protector::find_obf_association(uint32_t rva);

    bool    fuku_protector::test_regions();
    bool    fuku_protector::initialize_profiles();
    void    fuku_protector::merge_profiles(uint32_t dest_address_rva);
    bool    fuku_protector::fill_code(uint32_t dest_address_rva);
    bool    fuku_protector::finish_protected_code();
public:
    fuku_protector::fuku_protector(const shibari_module& module);
    fuku_protector::~fuku_protector();

public:
    fuku_protector_code fuku_protector::protect_module();

public:
    void fuku_protector::add_vm_profile(const std::vector<fuku_protected_region>& regions, const vm_fuku_settings& settings);
    void fuku_protector::add_ob_profile(const std::vector<fuku_protected_region>& regions, const ob_fuku_settings& settings);

    void fuku_protector::clear_profiles();
public:
    const shibari_module& get_target_module() const;
};


#pragma once

enum fuku_protector_code {
    fuku_protector_ok,
    fuku_protector_error_code_range,
    fuku_protector_error_initialization,
    fuku_protector_error_processing,
    fuku_protector_error_post_processing,
    fuku_protector_error_module_processing,
};

struct fuku_vm_environment {
    uint32_t virtual_machine_entry;
    fuku_virtualizer *  virtualizer;

    fuku_vm_environment();
    fuku_vm_environment(uint32_t virtual_machine_entry, fuku_virtualizer *  virtualizer);
    fuku_vm_environment(const fuku_vm_environment& env);
    bool operator==(const fuku_vm_environment& env) const;
    bool operator<(const fuku_vm_environment& rhs) const;
};

struct fuku_protection_item {
    fuku_code_analyzer an_code;
    fuku_ob_settings settings;
    std::vector<fuku_protected_region> regions;
};

struct fuku_protection_profile {
    std::vector<fuku_protected_region> regions;
    std::vector<fuku_code_association> association_table;
    std::vector<fuku_code_relocation>  relocation_table;

    std::vector<fuku_protection_item> items;
};



class fuku_protector {
    shibari_module target_module;

    fuku_protection_profile ob_profile;
    std::map<fuku_vm_environment, fuku_protection_profile> vm_profiles;

    fuku_code_association * fuku_protector::find_profile_association(fuku_protection_profile& profile, uint32_t rva);

    bool    fuku_protector::test_regions_scope();  
    bool    fuku_protector::initialize_profiles_vm();
    bool    fuku_protector::initialize_profiles_ob();
    bool    fuku_protector::obfuscate_profile();
    bool    fuku_protector::virtualize_profiles();

    bool    fuku_protector::finish_protected_ob_code();
    bool    fuku_protector::finish_protected_vm_code();
    bool    fuku_protector::finish_module();
public:
    fuku_protector::fuku_protector(const shibari_module& module);
    fuku_protector::~fuku_protector();

public:
    fuku_protector_code fuku_protector::protect_module();

public:
    void fuku_protector::add_vm_profile(const std::vector<fuku_protected_region>& regions, const fuku_vm_settings& settings);
    void fuku_protector::add_ob_profile(const std::vector<fuku_protected_region>& regions, const fuku_ob_settings& settings);

    void fuku_protector::clear_profiles();
public:
    const shibari_module& get_target_module() const;
};

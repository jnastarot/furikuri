#pragma once


enum fuku_protect_mgr_result {
    fuku_protect_ok,
    fuku_protect_err_code_range,
    fuku_protect_err_initialization,
    fuku_protect_err_processing,
    fuku_protect_err_post_processing,
    fuku_protect_err_module_processing,
};

struct fuku_vm_environment {
    uint32_t virtual_machine_entry;
    fuku_virtualizer *  virtualizer;

    fuku_vm_environment();
    fuku_vm_environment(uint32_t virtual_machine_entry, fuku_virtualizer *  virtualizer);
    fuku_vm_environment(const fuku_vm_environment& env);
    fuku_vm_environment& operator=(const fuku_vm_environment& env);
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
    std::vector<fuku_image_relocation>  relocation_table;

    std::vector<fuku_protection_item> items;
};



class fuku_protect_mgr {
    shibari_module target_module;

    fuku_protection_profile ob_profile;
    std::map<fuku_vm_environment, fuku_protection_profile> vm_profiles;

    fuku_code_association * find_profile_association(fuku_protection_profile& profile, uint32_t rva);

    bool test_regions_scope();  

    bool initialize_obfuscation_profiles();
    bool initialize_virtualization_profiles();

    bool process_obfuscation_profiles();
    bool process_virtualization_profiles();

    bool postprocess_obfuscation();
    bool postprocess_virtualization();

    bool    finish_module();
public:
    fuku_protect_mgr(const shibari_module& module);
    ~fuku_protect_mgr();

public:
    fuku_protect_mgr_result protect_module();

public:
    void add_vm_profile(const std::vector<fuku_protected_region>& regions, const fuku_vm_settings& settings);
    void add_ob_profile(const std::vector<fuku_protected_region>& regions, const fuku_ob_settings& settings);

    void clear_profiles();
public:
    const shibari_module& get_target_module() const;
};

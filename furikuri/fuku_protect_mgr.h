#pragma once


enum fuku_protect_mgr_result {
    fuku_protect_ok,
    fuku_protect_err_code_range,
    fuku_protect_err_initialization,
    fuku_protect_err_processing,
    fuku_protect_err_post_processing,
    fuku_protect_err_module_processing,
};


struct fuku_protected_region {
    uint32_t region_rva;
    uint32_t region_size;
};

struct fuku_protection_item {
    fuku_code_analyzer an_code;
    fuku_settings_obfuscation settings;
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
    std::map<
        fuku_virtualization_environment, 
        fuku_protection_profile
    > vm_profiles;

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
    void add_vm_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_virtualization& settings);
    void add_ob_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_obfuscation& settings);

    void clear_profiles();
public:
    const shibari_module& get_target_module() const;
};

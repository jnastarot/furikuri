#pragma once

enum fuku_protect_mgr_result {
    fuku_protect_ok,
    fuku_protect_err_code_range,
    fuku_protect_err_initialization,
    fuku_protect_err_processing,
    fuku_protect_err_post_processing,
    fuku_protect_err_module_processing,
};

enum fuku_protect_stage {
    fuku_protect_stage_start,
    fuku_protect_stage_check,
    fuku_protect_stage_initialization,
    fuku_protect_stage_processing,
    fuku_protect_stage_post_processing,
    fuku_protect_stage_finish_processing,
    fuku_protect_stage_full
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
    std::map<uint64_t, uint64_t>  association_table;
    std::vector<fuku_image_relocation>  relocation_table;

    std::vector<fuku_protection_item> items;
};


class fuku_settings_mgr {
    fuku_protect_stage stage_code;
    fuku_protect_mgr_result result_code;

    pe_image_full target_module;

    fuku_protection_profile ob_profile;

    std::map<
        fuku_virtualization_environment,
        fuku_protection_profile
    > vm_profiles;

    bool module_used_relocations;
public:
    fuku_settings_mgr();
    fuku_settings_mgr(const fuku_settings_mgr& mgr_set);
    ~fuku_settings_mgr();

    fuku_settings_mgr& operator=(const fuku_settings_mgr& mgr_set);

    void add_ob_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_obfuscation& settings);
    void add_vm_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_virtualization& settings);
public:

    void set_target_module(const pe_image_full& target_module);

    void set_ob_profile(const fuku_protection_profile& ob_profile);
    void set_vm_profiles(const std::map <
        fuku_virtualization_environment,
        fuku_protection_profile>& vm_profiles);

    void set_module_used_relocations(bool used);

    void set_result_code(fuku_protect_mgr_result code);
    void set_stage_code(fuku_protect_stage code);
public:

    pe_image_full& get_target_module();
    const pe_image_full& get_target_module() const;

    fuku_protection_profile& get_ob_profile();
    const fuku_protection_profile& get_ob_profile() const;

    std::map<
        fuku_virtualization_environment,
        fuku_protection_profile
    >& get_vm_profiles();

    const std::map<
        fuku_virtualization_environment,
        fuku_protection_profile
    >& get_vm_profiles() const;

    bool is_module_used_relocations() const;

    fuku_protect_mgr_result get_result_code() const;
    fuku_protect_stage get_stage_code() const;
};


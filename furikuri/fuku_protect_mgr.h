#pragma once

#include "fuku_settings_mgr.h"

class fuku_protect_mgr {
    
    fuku_settings_mgr settings;

    bool initialize_obfuscation_profiles();
    bool initialize_virtualization_profiles();

    bool process_obfuscation_profiles();
    bool process_virtualization_profiles();

    bool postprocess_obfuscation();
    bool postprocess_virtualization();

public:
    fuku_protect_mgr();
    fuku_protect_mgr(const fuku_settings_mgr& settings);

    ~fuku_protect_mgr();

public:
    fuku_protect_mgr_result step_to_stage(fuku_protect_stage stage);

public:
    bool check_regions_scope();
    bool initialize_profiles();
    bool process_profiles();
    bool post_process_profiles();
    bool finish_process_module();   
public:

    void add_vm_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_virtualization& settings);
    void add_ob_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_obfuscation& settings);

    void clear_profiles();

    void set_settings(const fuku_settings_mgr& settings);
public:

    fuku_settings_mgr& get_settings();
    const fuku_settings_mgr& get_settings() const;
};


bool protect_manager_create_stage_snapshot(
    fuku_settings_mgr& settings, fuku_protect_stage stage);
bool protect_manager_load_snapshot(
    fuku_protect_mgr& mgr, const fuku_settings_mgr& settings);
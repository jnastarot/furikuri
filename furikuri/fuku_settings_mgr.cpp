#include "stdafx.h"
#include "fuku_settings_mgr.h"


fuku_settings_mgr::fuku_settings_mgr()
    : result_code(fuku_protect_ok), stage_code(fuku_protect_stage_start), module_used_relocations(false) {}

fuku_settings_mgr::fuku_settings_mgr(const fuku_settings_mgr& mgr_set) {
    this->operator=(mgr_set);
}

fuku_settings_mgr::~fuku_settings_mgr() {}

fuku_settings_mgr& fuku_settings_mgr::operator=(const fuku_settings_mgr& mgr_set) {
   
    this->stage_code = mgr_set.stage_code;
    this->result_code = mgr_set.result_code;
    this->target_module = mgr_set.target_module;
    this->ob_profile = mgr_set.ob_profile;
    this->vm_profiles = mgr_set.vm_profiles;
    this->module_used_relocations = mgr_set.module_used_relocations;

    return *this;
}

void fuku_settings_mgr::set_target_module(const pe_image_full& target_module) {
    this->target_module = target_module;
}

void fuku_settings_mgr::set_ob_profile(const fuku_protection_profile& ob_profile) {
    this->ob_profile = ob_profile;
}

void fuku_settings_mgr::set_vm_profiles(const std::map <
    fuku_virtualization_environment,
    fuku_protection_profile>& vm_profiles) {

    this->vm_profiles = vm_profiles;
}

void fuku_settings_mgr::set_module_used_relocations(bool used) {
    this->module_used_relocations = used;
}

void fuku_settings_mgr::set_result_code(fuku_protect_mgr_result code) {
    this->result_code = code;
}

void fuku_settings_mgr::set_stage_code(fuku_protect_stage code) {
    this->stage_code = code;
}

pe_image_full& fuku_settings_mgr::get_target_module() {
    return this->target_module;
}
   
const pe_image_full& fuku_settings_mgr::get_target_module() const {
    return this->target_module;
}
    
fuku_protection_profile& fuku_settings_mgr::get_ob_profile() {
    return this->ob_profile;
}

const fuku_protection_profile& fuku_settings_mgr::get_ob_profile() const {
    return this->ob_profile;
}

std::map<
        fuku_virtualization_environment,
        fuku_protection_profile
>& fuku_settings_mgr::get_vm_profiles() {
    return this->vm_profiles;
}

const std::map<
        fuku_virtualization_environment,
        fuku_protection_profile
>& fuku_settings_mgr::get_vm_profiles() const {
    return this->vm_profiles;
}

bool fuku_settings_mgr::is_module_used_relocations() const {
    return this->module_used_relocations;
}

fuku_protect_mgr_result fuku_settings_mgr::get_result_code() const {
    return this->result_code;
}

fuku_protect_stage fuku_settings_mgr::get_stage_code() const {
    return this->stage_code;
}


void fuku_settings_mgr::add_ob_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_obfuscation& settings) {
    ob_profile.items.push_back({ fuku_code_analyzer() , settings, regions });
}

void fuku_settings_mgr::add_vm_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_virtualization& settings) {

    fuku_virtualization_environment env(settings.get_virtualizer());
    auto& vm_profile = vm_profiles.find(env);

    if (vm_profile != vm_profiles.end()) {
        vm_profile->second.items.push_back({ fuku_code_analyzer() , settings.get_obfuscation_settings(), regions });
    }
    else {
        vm_profiles[env] = {

            std::vector<fuku_protected_region>(),
            std::map<uint64_t, uint64_t>(),
            std::vector<fuku_image_relocation>(),

            std::vector<fuku_protection_item>(1,{ fuku_code_analyzer() , settings.get_obfuscation_settings(), regions })
        };
    }
}
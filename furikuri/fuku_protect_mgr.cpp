#include "stdafx.h"
#include "fuku_protect_mgr.h"


fuku_code_association * find_profile_association(fuku_settings_protect_mgr& settings, fuku_protection_profile& profile, uint32_t rva);

#include "fuku_protect_obfuscator_mgr.h"
#include "fuku_protect_virtualizer_mgr.h"




fuku_protect_mgr::fuku_protect_mgr() {}

fuku_protect_mgr::fuku_protect_mgr(const fuku_settings_protect_mgr& settings)
   : settings(settings) {}


fuku_protect_mgr::~fuku_protect_mgr() {
    clear_profiles();
}


fuku_protect_mgr_result fuku_protect_mgr::step_to_stage(fuku_protect_stage stage) {

    if (stage > settings.get_stage_code() && check_regions_scope()) {

        if (stage > settings.get_stage_code() && initialize_profiles()) {

            if (stage > settings.get_stage_code() && process_profiles()) {

                if (stage > settings.get_stage_code() && post_process_profiles()) {

                    if (stage > settings.get_stage_code()) {
                        finish_process_module();
                    }
                }
            }
        }
    }

    return settings.get_result_code();
}


bool fuku_protect_mgr::check_regions_scope() {

    if (settings.get_stage_code() == (fuku_protect_stage_check - 1)) {

        if (settings.get_result_code() == fuku_protect_ok) {

            settings.set_stage_code(fuku_protect_stage_check);

            bool result = true;

            std::vector<fuku_protected_region>   regions;

            for (auto& item : settings.get_ob_profile().items) {
                regions.insert(regions.end(), item.regions.begin(), item.regions.end());
            }

            for (auto& item : settings.get_vm_profiles()) {
                regions.insert(regions.end(), item.second.regions.begin(), item.second.regions.end());
            }


            std::sort(regions.begin(), regions.end(), [](fuku_protected_region& lhs, fuku_protected_region& rhs) {
                return lhs.region_rva < rhs.region_rva;
            });

            for (size_t region_idx = 0; region_idx < regions.size(); region_idx++) {

                if (region_idx + 1 < regions.size()) {
                    auto& region_current = regions[region_idx];
                    auto& region_next = regions[region_idx + 1];

                    if ((region_next.region_rva == region_current.region_rva) ||
                        (region_current.region_rva + region_current.region_size - 1) >= region_next.region_rva
                        ) {
                        result = false;
                        break;
                    }
                }
            }

            return result;
        }

        return false;
    }

    return settings.get_result_code() == fuku_protect_ok;
}

bool fuku_protect_mgr::initialize_profiles() {

    if (settings.get_stage_code() == (fuku_protect_stage_initialization - 1) ) {

        if (settings.get_result_code() == fuku_protect_ok) {

            settings.set_stage_code(fuku_protect_stage_initialization);

            bool result = initialize_obfuscation_profiles() && initialize_virtualization_profiles();

            if (!result) {
                settings.set_result_code(fuku_protect_err_initialization);
            }
            else {
                settings.set_result_code(fuku_protect_ok);
            }

            
            return result;
        }

        return false;
    }

    return settings.get_result_code() == fuku_protect_ok;
}

bool fuku_protect_mgr::process_profiles() {

    if (settings.get_stage_code() == (fuku_protect_stage_processing - 1)) {

        if (settings.get_result_code() == fuku_protect_ok) {

            settings.set_stage_code(fuku_protect_stage_processing);

            bool result = process_obfuscation_profiles() && process_virtualization_profiles();

            if (!result) {
                settings.set_result_code(fuku_protect_err_processing);
            }
            else {
                settings.set_result_code(fuku_protect_ok);
            }
     
            return result;
        }

        return false;
    }

    return settings.get_result_code() == fuku_protect_ok;
}

bool fuku_protect_mgr::post_process_profiles() {

    if (settings.get_stage_code() == (fuku_protect_stage_post_processing - 1)) {

        if (settings.get_result_code() == fuku_protect_ok) {

            settings.set_stage_code(fuku_protect_stage_post_processing);

            bool result = postprocess_obfuscation() && postprocess_virtualization();

            if (!result) {
                settings.set_result_code(fuku_protect_err_post_processing);
            }
            else {
                settings.set_result_code(fuku_protect_ok);
            }

            return result;
        }

        return false;
    }

    return settings.get_result_code() == fuku_protect_ok;
}

bool fuku_protect_mgr::finish_process_module() {
    //todo do configuration of configuration \_(0-0)_/

    if (settings.get_stage_code() == (fuku_protect_stage_finish_processing - 1)) {

        if (settings.get_result_code() == fuku_protect_ok) {

            pe_image_full& image_full = settings.get_target_module().get_module_image();

            settings.set_stage_code(fuku_protect_stage_finish_processing);

            bool result = true;

            image_full.get_load_config().get_se_handlers().clear();
            image_full.get_load_config().get_guard_cf_functions().clear();

            if (!result) {
                settings.set_result_code(fuku_protect_err_module_processing);
            }
            else {
                settings.set_result_code(fuku_protect_ok);
            }

            return result;
        }

        return false;
    }

    return settings.get_result_code() == fuku_protect_ok;
}

void fuku_protect_mgr::add_ob_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_obfuscation& settings) {
    this->settings.add_ob_profile(regions, settings);
}

void fuku_protect_mgr::add_vm_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_virtualization& settings) {
    this->settings.add_vm_profile(regions, settings);
}


void fuku_protect_mgr::clear_profiles() {
    settings.get_ob_profile().items.clear();
    settings.get_vm_profiles().clear();
}

void fuku_protect_mgr::set_settings(const fuku_settings_protect_mgr& settings) {
    this->settings = settings;
}

fuku_settings_protect_mgr& fuku_protect_mgr::get_settings() {
    return this->settings;
}

const fuku_settings_protect_mgr& fuku_protect_mgr::get_settings() const {
    return this->settings;
}

fuku_code_association * find_profile_association(fuku_settings_protect_mgr& settings, fuku_protection_profile& profile, uint32_t rva) {

    pe_image_full& image_full = settings.get_target_module().get_module_image();

    for (auto& region : profile.regions) {

        if (region.region_rva <= rva && region.region_rva + region.region_size > rva) {

            uint64_t real_address = image_full.get_image().rva_to_va((uint32_t)rva);

            size_t left = 0;
            size_t right = profile.association_table.size();
            size_t mid = 0;

            while (left < right) {
                mid = left + (right - left) / 2;

                if (profile.association_table[mid].original_virtual_address == real_address) {
                    return &profile.association_table[mid];
                }
                else if (profile.association_table[mid].original_virtual_address > real_address) {
                    right = mid;
                }
                else {
                    left = mid + 1;
                }
            }
        }
    }

    return 0;
}


bool protect_manager_create_stage_snapshot(fuku_settings_protect_mgr& settings, fuku_protect_stage stage) {
    fuku_protect_mgr mgr(settings);

    mgr.step_to_stage(stage);

    settings = mgr.get_settings();

    return settings.get_result_code() == fuku_protect_ok;
}

bool protect_manager_load_snapshot(fuku_protect_mgr& mgr, const fuku_settings_protect_mgr& settings) {
    
    mgr.get_settings() = settings;

    return true;
}
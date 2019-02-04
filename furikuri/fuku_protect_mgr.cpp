#include "stdafx.h"
#include "fuku_protect_mgr.h"


#include "fuku_protect_obfuscator_mgr.h"
#include "fuku_protect_virtualizer_mgr.h"




fuku_protect_mgr::fuku_protect_mgr(const shibari_module& _module)
    :target_module(_module) {
}


fuku_protect_mgr::~fuku_protect_mgr() {
    clear_profiles();
}


fuku_protect_mgr_result fuku_protect_mgr::protect_module() {

    if (test_regions_scope()) {

        if (initialize_obfuscation_profiles() && initialize_virtualization_profiles()) {

            if (process_obfuscation_profiles() && process_virtualization_profiles()) {

                if (postprocess_obfuscation() && postprocess_virtualization()) {

                    if (finish_module()) {

                        return fuku_protect_ok;
                    }

                    return fuku_protect_err_module_processing;
                }

                return fuku_protect_err_post_processing;
            }

            return fuku_protect_err_processing;
        }

        return fuku_protect_err_initialization;
    }

    return fuku_protect_err_code_range;
}



bool fuku_protect_mgr::test_regions_scope() {

    std::vector<fuku_protected_region>   regions;

    for (auto& item : ob_profile.items) {
        regions.insert(regions.end(), item.regions.begin(), item.regions.end());
    }

    for (auto& item : vm_profiles) {
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
                return false;
            }
        }
    }

    return true;
}

bool    fuku_protect_mgr::finish_module() {

    //todo do configuration of configuration \_(0-0)_/

    target_module.get_image_load_config().get_se_handlers().clear();
    target_module.get_image_load_config().get_guard_cf_functions().clear();

    return true;
}

fuku_code_association * fuku_protect_mgr::find_profile_association(fuku_protection_profile& profile, uint32_t rva) {

    for (auto& region : profile.regions) {
        
        if (region.region_rva <= rva && region.region_rva + region.region_size > rva) {
            uint64_t real_address = target_module.get_image().rva_to_va((uint32_t)rva);

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


void fuku_protect_mgr::clear_profiles() {
    ob_profile.items.clear();
    vm_profiles.clear();
}

const shibari_module& fuku_protect_mgr::get_target_module() const {
    return this->target_module;
}

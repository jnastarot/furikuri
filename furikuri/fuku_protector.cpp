#include "stdafx.h"
#include "fuku_protector.h"


#include "fuku_prot_ob.h"
#include "fuku_prot_vm.h"



fuku_vm_environment::fuku_vm_environment()
:virtualizer(0), virtual_machine_entry(0){}

fuku_vm_environment::fuku_vm_environment(uint32_t virtual_machine_entry, fuku_virtualizer *  virtualizer)
:virtual_machine_entry(virtual_machine_entry), virtualizer(virtualizer){}

fuku_vm_environment::fuku_vm_environment(const fuku_vm_environment& env) {
    this->virtualizer = env.virtualizer;
    this->virtual_machine_entry = env.virtual_machine_entry;
}

bool fuku_vm_environment::operator==(const fuku_vm_environment& env) const {
    return this->virtualizer == env.virtualizer && this->virtual_machine_entry == env.virtual_machine_entry;
}

bool fuku_vm_environment::operator<(const fuku_vm_environment& rhs) const {
    return this->virtualizer < rhs.virtualizer && this->virtual_machine_entry < rhs.virtual_machine_entry;
}

fuku_protector::fuku_protector(const shibari_module& _module)
    :target_module(_module) {
}


fuku_protector::~fuku_protector() {
    clear_profiles();
}


fuku_protector_code fuku_protector::protect_module() {

   // if (test_regions_scope()) {

        if (initialize_profiles_ob() && initialize_profiles_vm()) {

            if (obfuscate_profile() && virtualize_profiles()) {

                if (finish_protected_ob_code() && finish_protected_vm_code()) {

                    if (finish_module()) {

                        return fuku_protector_code::fuku_protector_ok;
                    }

                    return fuku_protector_code::fuku_protector_error_module_processing;
                }

                return fuku_protector_code::fuku_protector_error_post_processing;
            }

            return fuku_protector_code::fuku_protector_error_processing;
        }

        return fuku_protector_code::fuku_protector_error_initialization;
  //  }

    return fuku_protector_code::fuku_protector_error_code_range;
}



bool fuku_protector::test_regions_scope() {

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
                (region_current.region_rva + region_current.region_size) >= region_next.region_rva
                ) {
                return false;
            }
        }
    }

    return true;
}

bool    fuku_protector::finish_module() {

    target_module.get_image_load_config().get_se_handlers().clear();
    target_module.get_image_load_config().get_guard_cf_functions().clear();

    return true;
}

fuku_code_association * fuku_protector::find_profile_association(fuku_protection_profile& profile, uint32_t rva) {

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


void fuku_protector::clear_profiles() {
    ob_profile.items.clear();
    vm_profiles.clear();
}

const shibari_module& fuku_protector::get_target_module() const {
    return this->target_module;
}

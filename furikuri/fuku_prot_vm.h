#pragma once

bool    fuku_protector::initialize_profiles_vm() {

    pe_image_io image_io(target_module.get_image());
    bool     is32arch = target_module.get_image().is_x32_image();
    uint64_t base_address = target_module.get_image().get_image_base();

    target_module.get_image_relocations().sort();

    for (auto& profile : vm_profiles) {

        for (auto& item : profile.second.items) {
            item.an_code.set_arch(is32arch ? fuku_arch::fuku_arch_x32 : fuku_arch::fuku_arch_x64);
            
            std::sort(item.regions.begin(), item.regions.end(), [](fuku_protected_region& lhs, fuku_protected_region& rhs) {
                return lhs.region_rva < rhs.region_rva;
            });

            struct _bind_part_code {
                uint32_t rva_code_part;
                std::vector<uint8_t> code_buffer;
                std::vector<fuku_code_relocation> fuku_code_relocs;
            };

            std::vector<_bind_part_code> bind_part_code;

            size_t last_reloc_idx = 0;

            for (auto& region : item.regions) {

                _bind_part_code part_code;

                part_code.rva_code_part = region.region_rva;

                if (image_io.set_image_offset(region.region_rva).read(part_code.code_buffer, region.region_size) != enma_io_success) {
                    return false;
                }

                auto& relocations = target_module.get_image_relocations().get_items();

                for (size_t reloc_idx = last_reloc_idx; reloc_idx < relocations.size(); reloc_idx++, last_reloc_idx++) {
                    auto& reloc_item = relocations[reloc_idx];

                    if (reloc_item.relative_virtual_address > region.region_rva) {
                        if (reloc_item.relative_virtual_address < (region.region_rva + region.region_size)) {
                            part_code.fuku_code_relocs.push_back({
                                reloc_item.relative_virtual_address + base_address, reloc_item.relocation_id
                                });


                            relocations.erase(relocations.begin() + reloc_idx);

                            reloc_idx--;
                            last_reloc_idx--;
                        }
                        else {
                            break;
                        }
                    }
                }

                bind_part_code.push_back(part_code);

                image_io.set_image_offset(region.region_rva).memory_set(region.region_size, 0);
            }


            for (auto& part_code : bind_part_code) {
                item.an_code.push_code(
                    part_code.code_buffer.data(),
                    part_code.code_buffer.size(),
                    base_address + part_code.rva_code_part,
                    &part_code.fuku_code_relocs
                );
            }
        }
    }

    return true;
}

void fuku_protector::add_vm_profile(const std::vector<fuku_protected_region>& regions, const fuku_vm_settings& settings) {

    fuku_vm_environment env(settings._module->get_module_position().get_address_offset() + settings.vm_entry_rva , settings.virtualizer);
    auto& vm_profile = vm_profiles.find(env);

    if (vm_profile != vm_profiles.end()) {
        vm_profile->second.items.push_back({ fuku_code_analyzer() , settings.ob_settings, regions });
    }
    else {
      /*  vm_profiles[env] = { 
            std::pair<fuku_protection_profile, std::vector<uint8_t>>(
                {
                    std::vector<fuku_protected_region>(),
                    std::vector<fuku_code_association>(),
                    std::vector<fuku_code_relocation>(),

                    std::vector<fuku_protection_item>(1, { fuku_code_analyzer() , settings.ob_settings, regions })
                },
                std::vector<uint8_t>()
            )
        };
        */
    }
}


bool fuku_protector::virtualize_profiles() {



    return true;
}

bool    fuku_protector::finish_protected_vm_code() {


    return true;
}
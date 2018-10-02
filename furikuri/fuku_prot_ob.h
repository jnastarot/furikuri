#pragma once

void fuku_protector::add_ob_profile(const std::vector<fuku_protected_region>& regions, const fuku_ob_settings& settings) {
    ob_profile.items.push_back({ fuku_code_analyzer() , settings, regions });
}

bool    fuku_protector::initialize_profiles_ob() {

    pe_image_io image_io(target_module.get_image());
    bool     is32arch = target_module.get_image().is_x32_image();
    uint64_t base_address = target_module.get_image().get_image_base();

    for (auto& item : ob_profile.items) {
        item.an_code.set_arch(is32arch ? fuku_arch::fuku_arch_x32 : fuku_arch::fuku_arch_x64);

        std::sort(item.regions.begin(), item.regions.end(), [](fuku_protected_region& lhs, fuku_protected_region& rhs) {
            return lhs.region_rva < rhs.region_rva;
        });

        struct _bind_part_code {
            uint32_t rva_code_part;
            std::vector<uint8_t> code_buffer;
            std::vector<fuku_image_relocation> relocs;
        };

        std::vector<_bind_part_code> bind_part_code;

        target_module.get_image_relocations().sort();

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
                        part_code.relocs.push_back({
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
                &part_code.relocs
            );
        }
    }

    return true;
}

bool fuku_protector::obfuscate_profile() {

    if (ob_profile.items.size()) {

        pe_image_io image_io(target_module.get_image(), enma_io_mode::enma_io_mode_allow_expand);
        fuku_code_analyzer an_code;
        an_code.set_arch(target_module.get_image().is_x32_image() ? fuku_arch::fuku_arch_x32 : fuku_arch::fuku_arch_x64);

        for (int item_idx = ob_profile.items.size() - 1; item_idx >= 0; item_idx--) {
            auto& item = ob_profile.items[item_idx];

            fuku_obfuscator obfuscator;

            obfuscator.set_settings(item.settings);
            obfuscator.set_destination_virtual_address(target_module.get_image().get_image_base());
            obfuscator.set_code(item.an_code);

            obfuscator.obfuscate_code();

            if (!an_code.push_code(std::move(obfuscator.get_code()))) { return false; }


            ob_profile.regions.insert(ob_profile.regions.end(), item.regions.begin(), item.regions.end());

            ob_profile.items.erase(ob_profile.items.begin() + item_idx);
        }

        uint32_t dest_address_rva = ALIGN_UP(
            target_module.get_image().get_last_section()->get_virtual_address() +
            target_module.get_image().get_last_section()->get_virtual_size(), target_module.get_image().get_section_align());

        
        fuku_obfuscator obfuscator;
        obfuscator.set_association_table(&ob_profile.association_table);
        obfuscator.set_relocation_table(&ob_profile.relocation_table);
        obfuscator.set_settings({ 1, 1, 0, 5.f, 0 });

        obfuscator.set_destination_virtual_address(target_module.get_image().get_image_base() + dest_address_rva);

        obfuscator.set_code(an_code);
        an_code.clear();

        obfuscator.obfuscate_code();

        std::vector<uint8_t> ob_code = obfuscator.get_raw_code();

        if (image_io.set_image_offset(dest_address_rva).write(ob_code) != enma_io_success) { //todo //rewrite for dynamic code place
            return false;
        }

    }

    return true;
}

bool    fuku_protector::finish_protected_ob_code() {

    if (ob_profile.regions.size()) {

        fuku_asm_x86 fuku_asm;
        pe_image_io image_io(target_module.get_image());
        uint64_t base_address = target_module.get_image().get_image_base();
        auto&   image_relocs = target_module.get_image_relocations();
        bool     is32arch = target_module.get_image().is_x32_image();

        std::sort(ob_profile.association_table.begin(), ob_profile.association_table.end(), [](fuku_code_association& lhs, fuku_code_association& rhs) {
            return lhs.original_virtual_address < rhs.original_virtual_address;
        });

        for (auto& reloc : image_relocs.get_items()) {
            reloc.data = 0;
            if (image_io.set_image_offset(reloc.relative_virtual_address).read(
                &reloc.data, is32arch ? sizeof(uint32_t) : sizeof(uint64_t)) != enma_io_success) {

                return false;
            }
            reloc.data = target_module.get_image().va_to_rva(reloc.data);
        }


        for (auto& region : ob_profile.regions) {
            for (auto& reloc : image_relocs.get_items()) {                              //fix relocations

                if (reloc.data > region.region_rva &&
                    reloc.data < (region.region_rva + region.region_size)) {

                    fuku_code_association * assoc = find_profile_association(ob_profile, (uint32_t)reloc.data);

                    if (assoc) {
                        reloc.data = assoc->virtual_address;

                        if (image_io.set_image_offset(reloc.relative_virtual_address).write(
                            &reloc.data, is32arch ? sizeof(uint32_t) : sizeof(uint64_t)) != enma_io_success) {

                            return false;
                        }
                    }
                    else {
                        return false;
                    }
                }
            }

            fuku_code_association * dst_func_assoc = find_profile_association(ob_profile, region.region_rva);   //set jumps to start of obfuscated funcs
            if (dst_func_assoc) {
                auto _jmp = fuku_asm.jmp(uint32_t(dst_func_assoc->virtual_address - (region.region_rva + base_address) - 5));

                if (image_io.set_image_offset(region.region_rva).write(
                    _jmp.get_op_code(), _jmp.get_op_length()) != enma_io_success) {

                    return false;
                }
            }
        }

        for (auto& reloc : ob_profile.relocation_table) {
            image_relocs.add_item(uint32_t(reloc.virtual_address - base_address), reloc.relocation_id);
        }

        {
            fuku_code_association * ep_assoc = find_profile_association(ob_profile, target_module.get_image().get_entry_point());
            if (ep_assoc) {
                target_module.get_image().set_entry_point(uint32_t(ep_assoc->virtual_address - base_address));
            }
        }

        for (auto& ext_ep : target_module.get_module_entrys()) {
            fuku_code_association * ext_ep_assoc = find_profile_association(ob_profile, ext_ep.entry_point_rva);
            if (ext_ep_assoc) {
                ext_ep.entry_point_rva = uint32_t(ext_ep_assoc->virtual_address - base_address);
            }
        }


        for (auto& export_item : target_module.get_image_exports().get_items()) {

            fuku_code_association * item_assoc = find_profile_association(ob_profile, export_item.get_rva());
            if (item_assoc) {
                export_item.set_rva(uint32_t(item_assoc->virtual_address - base_address));
            }
        }
    }


    return true;
}


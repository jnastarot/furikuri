#pragma once

bool fuku_protect_mgr::initialize_virtualization_profiles() {

    pe_image_full& image_full = settings.get_target_module();
    pe_image_io image_io(image_full.get_image());
    bool     is32arch = image_full.get_image().is_x32_image();
    uint64_t base_address = image_full.get_image().get_image_base();

    fuku_code_profiler code_profiler(is32arch ? FUKU_ASSAMBLER_ARCH_X86 : FUKU_ASSAMBLER_ARCH_X64);

    image_full.get_relocations().sort();

    for (auto& profile : settings.get_vm_profiles()) {

        for (auto& item : profile.second.items) {
            item.an_code.set_arch(is32arch ? FUKU_ASSAMBLER_ARCH_X86 : FUKU_ASSAMBLER_ARCH_X64);

            std::sort(item.regions.begin(), item.regions.end(), [](fuku_protected_region& lhs, fuku_protected_region& rhs) {
                return lhs.region_rva < rhs.region_rva;
            });

            struct code_region_buffer {
                uint32_t code_rva;
                std::vector<uint8_t> code_buffer;
                std::vector<fuku_image_relocation> used_relocs;
            };

            std::vector<code_region_buffer> code_regions;


            size_t last_reloc_idx = 0;

            for (auto& region : item.regions) {

                code_region_buffer code_region;

                code_region.code_rva = region.region_rva;

                if (image_io.set_image_offset(region.region_rva).read(code_region.code_buffer, region.region_size) != enma_io_success) {
                    return false;
                }

                auto& relocations = image_full.get_relocations().get_entries();

                for (size_t reloc_idx = last_reloc_idx; reloc_idx < relocations.size(); reloc_idx++, last_reloc_idx++) {
                    auto& reloc_item = relocations[reloc_idx];

                    if (reloc_item.relative_virtual_address > region.region_rva) {
                        if (reloc_item.relative_virtual_address < (region.region_rva + region.region_size)) {

                            code_region.used_relocs.push_back({
                                reloc_item.relocation_id,
                                reloc_item.relative_virtual_address + base_address
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

                code_regions.push_back(code_region);

                image_io.set_image_offset(region.region_rva).memory_set(region.region_size, 0);
            }

            {
                fuku_assambler_ctx context;
                fuku_inst inst;

                context.arch = is32arch ? FUKU_ASSAMBLER_ARCH_X86 : FUKU_ASSAMBLER_ARCH_X64;
                context.inst = &inst;
                _jmp(context, imm(0));

                for (auto& code_region : code_regions) {

                    {
                        fuku_code_holder code_holder;

                        item.an_code.analyze_code(code_holder,
                            code_region.code_buffer.data(),
                            code_region.code_buffer.size(),
                            base_address + code_region.code_rva,
                            &code_region.used_relocs
                        );

                        if (code_holder.get_insts().size()) { //if taken a part of function we place a jmp to end of analyzed pieñe
                            uint16_t id = code_holder.get_insts().back().get_id();

                            if (id != X86_INS_JMP && id != X86_INS_RET) {

                                auto& _inst = code_holder.add_inst();

                                _inst = inst;

                                _inst.set_rip_reloc(
                                    code_holder.create_rip_relocation(
                                        fuku_rip_relocation()
                                        .set_offset(context.immediate_offset)
                                        .set_label(
                                            code_holder.create_label(
                                                fuku_code_label()
                                                .set_address(
                                                    code_holder.get_insts().back().get_source_address() +
                                                    code_holder.get_insts().back().get_oplength()
                                                )
                                            )
                                        )
                                    )
                                );

                            }
                        }

                        code_profiler.profile_code(code_holder);

                        item.an_code.push_code(code_holder);
                    }
                }
            }
        }
    }

    return true;
}

bool fuku_protect_mgr::process_virtualization_profiles() {

    if (settings.get_vm_profiles().size()) {

        pe_image_full& image_full = settings.get_target_module();
        pe_image_io image_io(image_full.get_image(), enma_io_mode::enma_io_mode_allow_expand);
        bool     is32arch = image_full.get_image().is_x32_image();

        image_io.seek_to_end();

        for (auto& profile : settings.get_vm_profiles()) {

            if (profile.second.items.size()) {

                fuku_code_analyzer anal_code;
                anal_code.set_arch(is32arch ? FUKU_ASSAMBLER_ARCH_X86 : FUKU_ASSAMBLER_ARCH_X64);

                size_t item_idx = profile.second.items.size();

                do {
                    item_idx--;

                    auto& item = profile.second.items[item_idx];

                    if (item.settings.is_null() != false) {
                        fuku_obfuscator obfuscator;

                        obfuscator.set_settings(item.settings);
                        obfuscator.set_destination_virtual_address(image_full.get_image().get_image_base());
                        obfuscator.set_code(&item.an_code.get_code());

                        obfuscator.obfuscate_code();

                        if (!anal_code.splice_code(item.an_code.get_code())) { FUKU_DEBUG; return false; }
                    }
                    else {
                        if (!anal_code.splice_code(item.an_code)) { FUKU_DEBUG; return false; }
                    }

                    profile.second.regions.insert(profile.second.regions.end(), item.regions.begin(), item.regions.end());
                    profile.second.items.erase(profile.second.items.begin() + item_idx);

                } while (item_idx);


                /*
                fuku_vm_result result = ((fuku_virtualization_environment&)profile.first).get_virtualizer()->build_bytecode(
                    settings.get_target_module(), anal_code.get_code(), std::vector<uint32_t>(), profile.second.relocation_table
                );
                */

               // if (result != fuku_vm_result::fuku_vm_ok) {

               //     FUKU_DEBUG;
               //     return false;
               // }

                if (image_io.write(profile.first.get_virtualizer()->get_bytecode()) != enma_io_success) {

                    FUKU_DEBUG;
                    return false;
                }
            }
        }
    }

    return true;
}

bool fuku_protect_mgr::postprocess_virtualization() {


    if (settings.get_vm_profiles().size()) {

        pe_image_full& image_full = settings.get_target_module();
        pe_image_io image_io(image_full.get_image());
        uint64_t base_address = image_full.get_image().get_image_base();
        auto&   image_relocs = image_full.get_relocations();
        bool    is32arch = image_full.get_image().is_x32_image();

        for (auto& profile : settings.get_vm_profiles()) {
            for (auto& region : profile.second.regions) {

                std::pair<uint64_t, uint64_t> assoc;


                //set jumps to start of virtualized funcs
                /* 
                if (find_profile_association(settings, profile.second, region.region_rva, assoc)) {

                    auto _jmp = profile.first.get_virtualizer()->create_vm_jumpout((region.region_rva + base_address), assoc.second,
                       profile.second.relocation_table);

                    if (image_io.set_image_offset(region.region_rva).write(_jmp) != enma_io_success) {

                        FUKU_DEBUG;
                        return false;
                    }

                } else {
                    FUKU_DEBUG;
                }
                */
            }

            for (auto& reloc : profile.second.relocation_table) {
                image_relocs.add_relocation(uint32_t(reloc.virtual_address - base_address), reloc.relocation_id,
                    is32arch ? IMAGE_REL_BASED_HIGHLOW : IMAGE_REL_BASED_DIR64);
            }
        }
    }

    return true;
}
#pragma once

void fuku_protect_mgr::add_ob_profile(const std::vector<fuku_protected_region>& regions, fuku_settings_obfuscation& settings) {
    ob_profile.items.push_back({ fuku_code_analyzer() , settings, regions });
}

bool fuku_protect_mgr::initialize_obfuscation_profiles() {

    pe_image_io image_io(target_module.get_image());
    bool     is32arch = target_module.get_image().is_x32_image();
    uint64_t base_address = target_module.get_image().get_image_base();

    fuku_code_profiler code_profiler(is32arch ? FUKU_ASSAMBLER_ARCH_X86 : FUKU_ASSAMBLER_ARCH_X64);

    target_module.get_image_relocations().sort();

    for (auto& item : ob_profile.items) {
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

                FUKU_DEBUG;
                return false;
            }

            auto& relocations = target_module.get_image_relocations().get_items();

            for (size_t reloc_idx = last_reloc_idx; reloc_idx < relocations.size(); reloc_idx++, last_reloc_idx++) {
                auto& reloc_item = relocations[reloc_idx];

                if (reloc_item.relative_virtual_address > region.region_rva) {
                    if (reloc_item.relative_virtual_address < (region.region_rva + region.region_size)) {

                        code_region.used_relocs.push_back({
                             reloc_item.relocation_id, reloc_item.relative_virtual_address + base_address
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
            fuku_instruction inst;

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

                    if (code_holder.get_lines().size()) { //if taken a part of function we place a jmp to end of analyzed pieñe
                        uint16_t id = code_holder.get_lines().back().get_id();

                        if (id != X86_INS_JMP && id != X86_INS_RET) {
                            code_holder.add_line() =
                                inst.set_rip_relocation_idx(
                                    code_holder.create_rip_relocation(
                                        context.immediate_offset,
                                        code_holder.get_lines().back().get_source_virtual_address() + code_holder.get_lines().back().get_op_length()
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

    return true;
}

bool fuku_protect_mgr::process_obfuscation_profiles() {

    if (ob_profile.items.size()) {

        pe_image_io image_io(target_module.get_image(), enma_io_mode::enma_io_mode_allow_expand);
        fuku_code_analyzer anal_code;
        anal_code.set_arch(target_module.get_image().is_x32_image() ? FUKU_ASSAMBLER_ARCH_X86 : FUKU_ASSAMBLER_ARCH_X64);

        if (ob_profile.items.size()) {
            size_t item_idx = ob_profile.items.size();

            do {
                item_idx--;

                auto& item = ob_profile.items[item_idx];

                fuku_obfuscator obfuscator;

                obfuscator.set_settings(item.settings);
                obfuscator.set_destination_virtual_address(target_module.get_image().get_image_base());
                obfuscator.set_code(&item.an_code.get_code());

                obfuscator.obfuscate_code();

                if (!anal_code.splice_code(item.an_code.get_code())) { FUKU_DEBUG; return false; }

                ob_profile.regions.insert(ob_profile.regions.end(), item.regions.begin(), item.regions.end());

                ob_profile.items.erase(ob_profile.items.begin() + item_idx);

            } while (item_idx);
        }

        uint32_t dest_address_rva = ALIGN_UP(
            target_module.get_image().get_last_section()->get_virtual_address() +
            target_module.get_image().get_last_section()->get_virtual_size(), target_module.get_image().get_section_align());

        
        fuku_obfuscator obfuscator;
        obfuscator.set_settings(fuku_settings_obfuscation(1, 1, 0, 5.f, 0 ,0));

        obfuscator.set_destination_virtual_address(target_module.get_image().get_image_base() + dest_address_rva);

        obfuscator.set_code(&anal_code.get_code());

        obfuscator.obfuscate_code();

        std::vector<uint8_t> ob_code = finalize_code(anal_code.get_code(), &ob_profile.association_table, &ob_profile.relocation_table);


        if (image_io.set_image_offset(dest_address_rva).write(ob_code) != enma_io_success) { 
            
            FUKU_DEBUG;

            //todo 
            /* rewrite for dynamic code place */

            /*
              when we take a part of code we clear and set this area to 0
               this area's (without first's 5 bytes) must be used for obfuscated and vmed code
            */
            
            return false;
        }

    }

    return true;
}

bool    fuku_protect_mgr::postprocess_obfuscation() {

    if (ob_profile.regions.size()) {

        fuku_assambler_ctx asm_ctx;
        fuku_instruction inst;

        asm_ctx.arch = FUKU_ASSAMBLER_ARCH_X86;
        asm_ctx.short_cfg = 0xFF;
        asm_ctx.inst = &inst;

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

                FUKU_DEBUG;
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

                            FUKU_DEBUG;
                            return false;
                        }
                    }
                    else {

                        FUKU_DEBUG;
                        return false;
                    }
                }
            }

            fuku_code_association * dst_func_assoc = find_profile_association(ob_profile, region.region_rva);   //set jumps to start of obfuscated funcs
            if (dst_func_assoc) {
                
                _jmp(asm_ctx, fuku_immediate(uint32_t(dst_func_assoc->virtual_address - (region.region_rva + base_address) - 5)));

                if (image_io.set_image_offset(region.region_rva).write(
                    asm_ctx.bytecode, asm_ctx.length) != enma_io_success) {
                    
                    FUKU_DEBUG;
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


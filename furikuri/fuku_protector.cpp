#include "stdafx.h"
#include "fuku_protector.h"


fuku_code_profile::fuku_code_profile() {
    type            = fuku_code_obfuscate;
    _ptr.obfuscator = 0;
    settings = { 0 };
}

fuku_code_profile::~fuku_code_profile() {

    if (_ptr.obfuscator) {

        if (type == fuku_code_obfuscate) {
            delete _ptr.obfuscator; _ptr.obfuscator = 0;           
        }
        else {
            delete _ptr.virtual_machine; _ptr.virtual_machine = 0;
        }
    }
}

fuku_protector::fuku_protector(const shibari_module& _module)
    :target_module(_module){


    main_obfuscator._ptr.obfuscator = new fuku_obfuscator;
    main_vm._ptr.virtual_machine = new fuku_virtual_machine;
}


fuku_protector::~fuku_protector(){
    clear_profiles();

    if (main_obfuscator._ptr.obfuscator) {
        delete main_obfuscator._ptr.obfuscator; main_obfuscator._ptr.obfuscator = 0;
    }
    if (main_vm._ptr.virtual_machine) {
        delete main_vm._ptr.virtual_machine; main_vm._ptr.virtual_machine = 0;
    }
}


fuku_protector_code fuku_protector::protect_module() {

    if (test_regions()) {

        if (initialize_profiles()) {

            uint32_t dest_address_rva = ALIGN_UP(
                target_module.get_image().get_last_section()->get_virtual_address() +
                target_module.get_image().get_last_section()->get_virtual_size(), target_module.get_image().get_section_align());
            uint64_t dest_address = target_module.get_image().get_image_base() + dest_address_rva;

            uint64_t last_address = dest_address;

            for (auto& profile : profiles) {

                switch (profile.type) {

                case fuku_code_obfuscate: {
                    profile._ptr.obfuscator = new fuku_obfuscator;
                    profile._ptr.obfuscator->set_association_table(&profile.association_table);
                    profile._ptr.obfuscator->set_relocation_table(&profile.relocation_table);
                    profile._ptr.obfuscator->set_ip_relocation_table(&profile.ip_relocation_table);
                    profile._ptr.obfuscator->set_settings(profile.settings);
                    profile._ptr.obfuscator->set_destination_virtual_address(last_address);
                    profile._ptr.obfuscator->set_code(profile.analyzed_code);

                    profile._ptr.obfuscator->obfuscate_code();

                    const std::vector<fuku_instruction>& lines = profile._ptr.obfuscator->get_lines();
                    last_address += lines[lines.size() - 1].get_virtual_address() + lines[lines.size() - 1].get_op_length();
                    break;
                }

                case fuku_code_hybrid: {
                    fuku_obfuscator obfuscator;

                    obfuscator.set_settings({ 2 , 2, 5.f, 5.f , 20.f});
                    obfuscator.set_destination_virtual_address(last_address);
                    obfuscator.set_code(profile.analyzed_code);

                    obfuscator.obfuscate_code();

                    profile.analyzed_code.clear();
                    profile.analyzed_code.push_code(obfuscator.get_lines());

                    const std::vector<fuku_instruction>& lines = obfuscator.get_lines();
                    last_address += lines[lines.size() - 1].get_virtual_address() + lines[lines.size() - 1].get_op_length();
                    break;
                }

                case fuku_code_virtual: {
                    profile._ptr.virtual_machine = new fuku_virtual_machine;
                    break;
                }
                

                }

            }

            merge_profiles(dest_address_rva);

            if (!fill_code(dest_address_rva)) {
                return fuku_protector_code::fuku_protector_error_initialization;
            }

            if (finish_protected_code()) {
                return fuku_protector_code::fuku_protector_ok;
            }
        }

        return fuku_protector_code::fuku_protector_error_initialization;
    }

    return fuku_protector_code::fuku_protector_error_code_range;
}


bool    fuku_protector::initialize_profiles() {

    pe_image_io image_io(target_module.get_image());
    bool     is32arch = target_module.get_image().is_x32_image();
    uint64_t base_address = target_module.get_image().get_image_base();

    for (auto& profile : profiles) {

        profile.analyzed_code.set_arch(is32arch ? fuku_arch::fuku_arch_x32 : fuku_arch::fuku_arch_x64);

        std::sort(profile.regions.begin(), profile.regions.end(), [](fuku_protected_region& lhs, fuku_protected_region& rhs) {
            return lhs.region_rva < rhs.region_rva;
        });


        struct _bind_part_code {
            uint32_t rva_code_part;
            std::vector<uint8_t> code_buffer;
            std::vector<fuku_code_relocation> fuku_code_relocs;
        };

        std::vector<_bind_part_code> bind_part_code;

        target_module.get_image_relocations().sort();

        size_t last_reloc_idx = 0;

        for (auto& region : profile.regions) {

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
        profile.analyzed_code.push_code(
            part_code.code_buffer.data(), 
            part_code.code_buffer.size(),
            base_address + part_code.rva_code_part, 
            &part_code.fuku_code_relocs
        );
    }


    }

    return true;
}

void    fuku_protector::merge_profiles(uint32_t dest_address_rva) {
    
    fuku_code_analyzer totaly_obfuscated_code;
    fuku_code_analyzer totaly_vmed_code;

    totaly_obfuscated_code.set_arch(
        target_module.get_image().is_x32_image() ? fuku_arch::fuku_arch_x32 : fuku_arch::fuku_arch_x64
    );
    totaly_vmed_code.set_arch(
        target_module.get_image().is_x32_image() ? fuku_arch::fuku_arch_x32 : fuku_arch::fuku_arch_x64
    );

    for (auto& profile : profiles) {

        switch (profile.type) {

        case fuku_code_obfuscate: {
            totaly_obfuscated_code.push_code(profile._ptr.obfuscator->get_lines());

            main_obfuscator.regions.insert(main_obfuscator.regions.end(),profile.regions.begin(), profile.regions.end());
            break;
        }

        case fuku_code_hybrid:
        case fuku_code_virtual: {
            totaly_vmed_code.push_code(profile.analyzed_code.get_lines());
            break;
        }
        }
    }

    uint64_t dest_address = target_module.get_image().get_image_base() + dest_address_rva;

    main_obfuscator._ptr.obfuscator->set_association_table(&main_obfuscator.association_table);
    main_obfuscator._ptr.obfuscator->set_relocation_table(&main_obfuscator.relocation_table);
    main_obfuscator._ptr.obfuscator->set_ip_relocation_table(&main_obfuscator.ip_relocation_table);
    main_obfuscator._ptr.obfuscator->set_settings({1 , 1 , 0.f , 5.f , 0.f}); //only for mixing

    main_obfuscator._ptr.obfuscator->set_destination_virtual_address(dest_address);

    main_obfuscator._ptr.obfuscator->set_code(totaly_obfuscated_code);

    main_obfuscator._ptr.obfuscator->obfuscate_code();
    //main_vm.set_code()


}

bool    fuku_protector::fill_code(uint32_t dest_address_rva) {

    pe_image_io image_io(target_module.get_image(), enma_io_mode::enma_io_mode_allow_expand);

    std::vector<uint8_t> ob_code = main_obfuscator._ptr.obfuscator->get_code();

    //rewrite for dynamic code place
    if (ob_code.size()) {
        if (image_io.set_image_offset(dest_address_rva).write(ob_code) != enma_io_success) {
            return false;
        }
    }

    return true;
}

bool    fuku_protector::finish_protected_code() {

    sort_association_tables();
    auto& image_relocs = target_module.get_image_relocations();

    fuku_asm_x86 fuku_asm;
    pe_image_io image_io(target_module.get_image());

    uint64_t base_address = target_module.get_image().get_image_base();

	
    for (auto& reloc : image_relocs.get_items()) {
        reloc.data = 0;
        if (image_io.set_image_offset(reloc.relative_virtual_address).read(
            &reloc.data, target_module.get_image().is_x32_image() ? sizeof(uint32_t) : sizeof(uint64_t)) != enma_io_success) {

            return false;
        }
        reloc.data = target_module.get_image().va_to_rva(reloc.data);
    }

    if(main_obfuscator._ptr.obfuscator->get_lines().size()) {

        for (auto& region : main_obfuscator.regions) {
            for (auto& reloc : image_relocs.get_items()) {                              //fix relocations

                if (reloc.data > region.region_rva &&
                    reloc.data < (region.region_rva + region.region_size)) {

                    fuku_code_association * assoc = find_obf_association((uint32_t)reloc.data);

                    if (assoc) {
                        reloc.data = assoc->virtual_address;

                        if (image_io.set_image_offset(reloc.relative_virtual_address).write(
                            &reloc.data, target_module.get_image().is_x32_image() ? sizeof(uint32_t) : sizeof(uint64_t)) != enma_io_success) {

                            return false;
                        }
                    }
                    else {
                        return false;
                    }
                }
            }

            fuku_code_association * dst_func_assoc = find_obf_association(region.region_rva);   //set jumps to start of obfuscated funcs
            if (dst_func_assoc) {
                auto _jmp = fuku_asm.jmp(uint32_t(dst_func_assoc->virtual_address - (region.region_rva + base_address) - 5));

                if (image_io.set_image_offset(region.region_rva).write(
                    _jmp.get_op_code(), _jmp.get_op_length()) != enma_io_success) {

                    return false;
                }
            }
        }

        for (auto& reloc : main_obfuscator.relocation_table) {

            uint32_t rel = uint32_t(reloc.virtual_address - base_address);

            image_relocs.add_item(rel, reloc.relocation_id);
        }
    }

    
    {
        fuku_code_association * ep_assoc = find_obf_association(target_module.get_image().get_entry_point());
        if (ep_assoc) {
            target_module.get_image().set_entry_point(uint32_t(ep_assoc->virtual_address - base_address));
        }
    }

    for (auto& ext_ep : target_module.get_module_entrys()) {
        fuku_code_association * ext_ep_assoc = find_obf_association(ext_ep.entry_point_rva);
        if (ext_ep_assoc) {
            ext_ep.entry_point_rva = uint32_t(ext_ep_assoc->virtual_address - base_address);
        }
    }

    target_module.get_image_load_config().get_se_handlers().clear();
    target_module.get_image_load_config().get_guard_cf_functions().clear();

    for (auto& export_item : target_module.get_image_exports().get_items()) {

        fuku_code_association * item_assoc = find_obf_association(export_item.get_rva());
        if (item_assoc) {
            export_item.set_rva(uint32_t(item_assoc->virtual_address - base_address));
        }
    }

    return true;
}

bool fuku_protector::test_regions() {

    std::vector<fuku_protected_region>   regions;

    for (auto& profile : profiles) {
        for (auto& region : profile.regions) {
            regions.push_back(region);
        }
    }

    std::sort(regions.begin(), regions.end(), [](fuku_protected_region& lhs, fuku_protected_region& rhs) {
        return lhs.region_rva < rhs.region_rva;
    });

    for (size_t region_idx = 0; region_idx < regions.size(); region_idx++) {

        if (region_idx + 1 < regions.size()) {
            auto& region_current = regions[region_idx];
            auto& region_next = regions[region_idx + 1];

            if ( (region_next.region_rva == region_current.region_rva) || 
                (region_current.region_rva + region_current.region_size) >= region_next.region_rva
                ) {
                return false;
            }
        }
    }

    return true;
}

void    fuku_protector::sort_association_tables() {
   /* for (auto& profile : profiles) {
        std::sort(profile.association_table.begin(), profile.association_table.end(), [](fuku_code_association& lhs, fuku_code_association& rhs) {
            return lhs.prev_virtual_address < rhs.prev_virtual_address;
        });
    }*/

    std::sort(main_obfuscator.association_table.begin(), main_obfuscator.association_table.end(), [](fuku_code_association& lhs, fuku_code_association& rhs) {
        return lhs.prev_virtual_address < rhs.prev_virtual_address;
    });
}

fuku_code_association * fuku_protector::find_obf_association(uint32_t rva){

    
    for (auto& region : main_obfuscator.regions) {

        if (region.region_rva <= rva && region.region_rva + region.region_size > rva) {
            uint64_t real_address = target_module.get_image().rva_to_va((uint32_t)rva);

            size_t left = 0;
            size_t right = main_obfuscator.association_table.size();
            size_t mid = 0;

            while (left < right) {
                mid = left + (right - left) / 2;

                if (main_obfuscator.association_table[mid].prev_virtual_address == real_address) {
                    return &main_obfuscator.association_table[mid];
                }
                else if (main_obfuscator.association_table[mid].prev_virtual_address > real_address) {
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


void fuku_protector::add_vm_profile(const std::vector<fuku_protected_region>& regions, const vm_fuku_settings& settings) {

    fuku_code_profile code_profile;
    code_profile.regions = regions;

    if (settings.used_obfuscation) {
        code_profile.type = fuku_code_type::fuku_code_hybrid;
    }
    else {
        code_profile.type = fuku_code_type::fuku_code_virtual;
    }

    //code_profile.settings = settings;

    profiles.push_back(code_profile);
}

void fuku_protector::add_ob_profile(const std::vector<fuku_protected_region>& regions, const ob_fuku_settings& settings) {

    fuku_code_profile code_profile;
    code_profile.regions = regions;

    code_profile.type = fuku_code_type::fuku_code_obfuscate;
    code_profile.settings = settings;

    profiles.push_back(code_profile);
}


void fuku_protector::clear_profiles() {
    profiles.clear();
}

const shibari_module& fuku_protector::get_target_module() const {
    return this->target_module;
}
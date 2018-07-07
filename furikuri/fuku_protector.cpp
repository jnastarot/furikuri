#include "stdafx.h"
#include "fuku_protector.h"


fuku_code_profile::fuku_code_profile() {
    out_code_rva    = 0;
    type            = fuku_code_obfuscate;
    _ptr.obfuscator = 0;
}

fuku_code_profile::~fuku_code_profile() {

    if (_ptr.obfuscator) {

        if (type == fuku_code_obfuscate) {
            delete _ptr.obfuscator;
        }
        else {
            delete _ptr.virtual_machine;
        }
    }
}

fuku_protector::fuku_protector(const shibari_module& _module)
    :protected_module(_module){

}


fuku_protector::~fuku_protector(){
    clear_profiles();
}


/*
fuku_protector_code fuku_protector::protect_module() {

    if (start_initialize_zones()) {
        pe_image_io image_io(module->get_image(), enma_io_mode_allow_expand);

        uint64_t base_address = module->get_image().get_image_base();
        uint32_t dest_address_rva =  ALIGN_UP(
                module->get_image().get_last_section()->get_virtual_address() +
                module->get_image().get_last_section()->get_virtual_size(), module->get_image().get_section_align());
        uint64_t dest_address = base_address + dest_address_rva;

        module->get_image().get_last_section()->set_executable(true);

        obfuscator.set_destination_virtual_address(dest_address);

        std::vector<uint8_t> ob_code = obfuscator.obfuscate_code();

        if (image_io.set_image_offset(dest_address_rva).write(ob_code) != enma_io_success) {
            return false;
        }

       
        if (finish_initialize_zones()) {
            return true;
        }
    }

    return false;
}


bool fuku_protector::start_initialize_zones() {

    if (code_list.code_placement.size()) {
        pe_image_io image_io(module->get_image(), enma_io_mode_allow_expand);

        uint64_t base_address = module->get_image().get_image_base();

        struct _bind_part_code {
            uint32_t rva_code_part;
            std::vector<uint8_t> code_buffer;
            std::vector<ob_fuku_relocation> fuku_code_relocs;
        };

        std::vector<_bind_part_code> bind_part_code;

        module->get_image_relocations().sort();

        std::sort(code_list.code_placement.begin(), code_list.code_placement.end(), [](shibari_module_symbol_info& lhs, shibari_module_symbol_info& rhs) {
            return lhs.symbol_info_rva < rhs.symbol_info_rva;
        });

        uint32_t top_reloc_idx = 0;

        for (auto& code : code_list.code_placement) {
            _bind_part_code part_code;

            part_code.rva_code_part = code.symbol_info_rva;

            if (image_io.set_image_offset(code.symbol_info_rva).read(part_code.code_buffer, code.symbol_info_size) != enma_io_success) {
                return false;
            }

            auto& relocations = module->get_image_relocations().get_items();

            for (uint32_t reloc_idx = top_reloc_idx; reloc_idx < relocations.size(); reloc_idx++, top_reloc_idx++) {
                auto& reloc_item = relocations[reloc_idx];

                if (reloc_item.relative_virtual_address > code.symbol_info_rva) {
                    if (reloc_item.relative_virtual_address < (code.symbol_info_rva + code.symbol_info_size)) {
                        part_code.fuku_code_relocs.push_back({ 
                            reloc_item.relative_virtual_address + base_address, reloc_item.relocation_id
                        });

                        relocations.erase(relocations.begin() + reloc_idx);

                        reloc_idx--;
                        top_reloc_idx--;
                    }
                    else {
                        break;
                    }
                }
            }

            bind_part_code.push_back(part_code);

            image_io.set_image_offset(code.symbol_info_rva).memory_set(code.symbol_info_size, 0);
        }


        for (auto& part_code : bind_part_code) {
            obfuscator.push_code(part_code.code_buffer.data(), part_code.code_buffer.size(),
                module->get_image().get_image_base() + part_code.rva_code_part, &part_code.fuku_code_relocs);
        }


        return true;
    }

    return false;
}

bool    fuku_protector::finish_initialize_zones() {

    sort_assoc();
    auto& image_relocs = module->get_image_relocations();

    fuku_asm_x86 fuku_asm;
    pe_image_io image_io(module->get_image());
    
    uint64_t base_address = module->get_image().get_image_base();

    for (auto& reloc : image_relocs.get_items()) {
        reloc.data = 0;
        if (image_io.set_image_offset(reloc.relative_virtual_address).read(
            &reloc.data, module->get_image().is_x32_image() ? sizeof(uint32_t) : sizeof(uint64_t)) != enma_io_success) {

            return false;
        }
        reloc.data = this->module->get_image().va_to_rva(reloc.data);
    }


    for (auto& code : code_list.code_placement) {
        for (auto& reloc : image_relocs.get_items()) {

            if (reloc.data  > code.symbol_info_rva &&
                reloc.data < (code.symbol_info_rva + code.symbol_info_size)) {

                ob_fuku_association * assoc = find_assoc(this->module->get_image().rva_to_va((uint32_t)reloc.data));

                if (assoc) {
                    reloc.data = assoc->virtual_address;

                    if (image_io.set_image_offset(reloc.relative_virtual_address).write(
                        &reloc.data, module->get_image().is_x32_image() ? sizeof(uint32_t) : sizeof(uint64_t)) != enma_io_success) {

                        return false;
                    }
                }
                else {
                    return false;
                }
            }
        }
    }

    

    for (auto func : code_list.func_starts) {

        ob_fuku_association * dst_func_assoc = find_assoc(func + base_address);
        if (dst_func_assoc) {
            auto _jmp = fuku_asm.jmp( uint32_t(dst_func_assoc->virtual_address - (func + base_address) - 5));

            if (image_io.set_image_offset(func).write(
                _jmp.get_op_code(), _jmp.get_op_length()) != enma_io_success) {

                return false;
            }
        }
    }

    for (auto& reloc : relocation_table) {
        image_relocs.add_item(uint32_t(reloc.virtual_address - base_address), reloc.relocation_id);
    }

    {
        ob_fuku_association * ep_assoc = find_assoc(module->get_image().get_entry_point() + base_address);
        if (ep_assoc) {
            module->get_image().set_entry_point(uint32_t(ep_assoc->virtual_address - base_address));
        }
    }

    for (auto& ext_ep : module->get_module_entrys()) {
        ob_fuku_association * ext_ep_assoc = find_assoc(ext_ep.entry_point_rva + base_address);
        if (ext_ep_assoc) {
            ext_ep.entry_point_rva = uint32_t(ext_ep_assoc->virtual_address - base_address);
        }
    }

    module->get_image_load_config().get_se_handlers().clear();
    module->get_image_load_config().get_guard_cf_functions().clear();

    for (auto& export_item : module->get_image_exports().get_items()) {

        ob_fuku_association * item_assoc = find_assoc(export_item.get_rva() + base_address);
        if (item_assoc) {
            export_item.set_rva(uint32_t(item_assoc->virtual_address - base_address));
        }
    }

    return true;
}
*/

fuku_protector_code fuku_protector::protect_module() {

    if (test_regions()) {

        if (initialize_profiles()) {

            for (auto& profile : profiles) {

                switch (profile.type) {

                case fuku_code_obfuscate: {
                    profile._ptr.obfuscator = new fuku_obfuscator;


                    break;
                }

                case fuku_code_hybrid: {

                    break;
                }
                case fuku_code_virtual: {
                    profile._ptr.virtual_machine = new fuku_virtual_machine;


                    break;
                }
                

                }

            }

            merge_profiles();

            if (finish_protected_code()) {
                return fuku_protector_code::fuku_protector_ok;
            }
        }

        return fuku_protector_code::fuku_protector_error_initialization;
    }

    return fuku_protector_code::fuku_protector_error_code_range;
}


bool    fuku_protector::initialize_profiles() {

    pe_image_io image_io(protected_module.get_image());
    bool     is32arch = protected_module.get_image().is_x32_image();
    uint64_t base_address = protected_module.get_image().get_image_base();

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

        protected_module.get_image_relocations().sort();

        size_t last_reloc_idx = 0;

        for (auto& region : profile.regions) {

            _bind_part_code part_code;

            part_code.rva_code_part = region.region_rva;

            if (image_io.set_image_offset(region.region_rva).read(part_code.code_buffer, region.region_size) != enma_io_success) {
                return false;
            }

            auto& relocations = protected_module.get_image_relocations().get_items();

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

void    fuku_protector::merge_profiles() {
    //merge external jumps
}

bool    fuku_protector::finish_protected_code() {


    return false;
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
    for (auto& profile : profiles) {
        std::sort(profile.association_table.begin(), profile.association_table.end(), [](fuku_code_association& lhs, fuku_code_association& rhs) {
            return lhs.prev_virtual_address < rhs.prev_virtual_address;
        });
    }
}

fuku_code_association * fuku_protector::find_association(fuku_code_profile& profile, uint32_t rva){

    
    for (auto& region : profile.regions) {

        if (region.region_rva <= rva && region.region_rva + region.region_size > rva) {
            uint64_t real_address = protected_module.get_image().rva_to_va(rva);

            size_t left = 0;
            size_t right = profile.association_table.size();
            size_t mid = 0;

            while (left < right) {
                mid = left + (right - left) / 2;

                if (profile.association_table[mid].prev_virtual_address == real_address) {
                    return &profile.association_table[mid];
                }
                else if (profile.association_table[mid].prev_virtual_address > real_address) {
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

fuku_code_association * fuku_protector::find_association(uint32_t rva) {

    for (auto& profile : profiles) {
        fuku_code_association * code_assoc = find_association(profile, rva);
        if (code_assoc) {
            return code_assoc;
        }
    }

    return 0;
}


void fuku_protector::add_profile(const std::vector<fuku_protected_region>& regions, fuku_code_type type) {

    fuku_code_profile code_profile;
    code_profile.regions = regions;
    code_profile.out_code_rva = 0;
    code_profile.type    = type;


    profiles.push_back(code_profile);
}


void fuku_protector::clear_profiles() {
    profiles.clear();
}

const shibari_module& fuku_protector::get_protected_module() const {
    return this->protected_module;
}
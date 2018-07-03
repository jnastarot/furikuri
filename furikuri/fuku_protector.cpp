#include "stdafx.h"
#include "fuku_protector.h"


fuku_protector::fuku_protector(shibari_module * module, const ob_fuku_sensitivity& settings,
    const fuku_code_list& code_list)
    :module(module), code_list(code_list){

    obfuscator.set_arch(
        module->get_image().is_x32_image() ? fuku_arch::fuku_arch_x32 : fuku_arch::fuku_arch_x64
    );
    obfuscator.set_settings(settings);
    obfuscator.set_association_table(&association_table);
    obfuscator.set_relocation_table(&relocation_table);
}


fuku_protector::~fuku_protector()
{
}



bool fuku_protector::protect_module() {

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

void fuku_protector::sort_assoc() {
    std::sort(association_table.begin(), association_table.end(), [](ob_fuku_association& lhs, ob_fuku_association& rhs) {
        return lhs.prev_virtual_address < rhs.prev_virtual_address;
    });
}

ob_fuku_association * fuku_protector::find_assoc(uint64_t rva) {

    size_t left = 0;
    size_t right = association_table.size();
    size_t mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (association_table[mid].prev_virtual_address == rva) {
            return &association_table[mid];
        }
        else if (association_table[mid].prev_virtual_address > rva) {
            right = mid;
        }
        else {
            left = mid + 1;
        }
    }

    return 0;
}
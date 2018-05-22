#include "stdafx.h"
#include "fuku_protector.h"


fuku_protector::fuku_protector(shibari_module * module, const ob_fuku_sensitivity& settings,
    const fuku_code_list& code_list)
    :module(module), code_list(code_list){

    obfuscator.set_arch(
        module->get_image().is_x32_image() ? ob_fuku_arch::ob_fuku_arch_x32 : ob_fuku_arch::ob_fuku_arch_x64
    );
    obfuscator.set_settings(settings);
    obfuscator.set_association_table(&assoc_table);
    obfuscator.set_relocation_table(&reloc_table);
    obfuscator.set_ip_relocation_table(&ip_reloc_table);
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

        module->get_image_relocations().sort();

        for (auto& code : code_list.code_placement) {
            std::vector<uint8_t> code_buffer;

            if (image_io.set_image_offset(code.symbol_info_rva).read(code_buffer, code.symbol_info_size) != enma_io_success) {
                return false;
            }

            std::vector<relocation_item> image_code_relocs;
            module->get_image_relocations().get_items_by_segment(image_code_relocs, code.symbol_info_rva, code.symbol_info_size);
            module->get_image_relocations().erase_all_items_in_zone(code.symbol_info_rva, code.symbol_info_size);

            std::vector<ob_fuku_relocation> fuku_code_relocs;

            for (auto& code_reloc : image_code_relocs) {
                fuku_code_relocs.push_back({ code_reloc.relative_virtual_address + base_address, code_reloc.relocation_id });
            }

            obfuscator.push_code(code_buffer.data(), code.symbol_info_size, 
                module->get_image().get_image_base() + code.symbol_info_rva, &fuku_code_relocs);

            image_io.set_image_offset(code.symbol_info_rva).memory_set(code.symbol_info_size, 0);
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

    for (auto& code : code_list.code_placement) {
        for (auto& reloc : image_relocs.get_items()) {

            uint64_t rel_dst = 0;
            image_io.set_image_offset(reloc.relative_virtual_address).read(&rel_dst, sizeof(rel_dst));


            if (image_io.set_image_offset(reloc.relative_virtual_address).read(
                &rel_dst, module->get_image().is_x32_image() ? sizeof(uint32_t) : sizeof(uint64_t)) != enma_io_success) {

                return false;
            }

            if (rel_dst > code.symbol_info_rva &&
                rel_dst < (code.symbol_info_rva + code.symbol_info_size)) {

                ob_fuku_association * assoc = find_assoc(rel_dst);

                if (assoc) {
                    rel_dst = assoc->virtual_address;

                    if (image_io.set_image_offset(reloc.relative_virtual_address).write(
                        &rel_dst, module->get_image().is_x32_image() ? sizeof(uint32_t) : sizeof(uint64_t)) != enma_io_success) {

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
            auto _jmp = fuku_asm.jmp(dst_func_assoc->virtual_address - (func + base_address) - 5);

            if (image_io.set_image_offset(func).write(
                _jmp.get_op_code(), _jmp.get_op_length()) != enma_io_success) {

                return false;
            }
        }
    }

    for (auto& reloc : reloc_table) {
        image_relocs.add_item(reloc.virtual_address - base_address, reloc.relocation_id);
    }

    {
        ob_fuku_association * ep_assoc = find_assoc(module->get_image().get_entry_point() + base_address);
        if (ep_assoc) {
            module->get_image().set_entry_point(ep_assoc->virtual_address - base_address);
        }
    }

    for (auto& ext_ep : module->get_module_entrys()) {
        ob_fuku_association * ext_ep_assoc = find_assoc(ext_ep.entry_point_rva + base_address);
        if (ext_ep_assoc) {
            ext_ep.entry_point_rva = ext_ep_assoc->virtual_address - base_address;
        }
    }

    module->get_image_load_config().get_se_handlers().clear();
    module->get_image_load_config().get_guard_cf_functions().clear();

    for (auto& export_item : module->get_image_exports().get_items()) {

        ob_fuku_association * item_assoc = find_assoc(export_item.get_rva() + base_address);
        if (item_assoc) {
            export_item.set_rva(item_assoc->virtual_address - base_address);
        }
    }

    return true;
}

void                  fuku_protector::sort_assoc() {
    std::sort(assoc_table.begin(), assoc_table.end(), [](ob_fuku_association& lhs, ob_fuku_association& rhs) {
        return lhs.prev_virtual_address < rhs.prev_virtual_address;
    });
}

ob_fuku_association * fuku_protector::find_assoc(uint32_t rva) {

    size_t left = 0;
    size_t right = assoc_table.size();
    size_t mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (assoc_table[mid].prev_virtual_address == rva) {
            return &assoc_table[mid];
        }
        else if (assoc_table[mid].prev_virtual_address > rva) {
            right = mid;
        }
        else {
            left = mid + 1;
        }
    }

    return 0;
}
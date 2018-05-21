#include "stdafx.h"
#include "fuku_protector.h"


fuku_protector::fuku_protector(shibari_module * module, const ob_fuku_sensitivity& settings)
    :module(module), settings(settings){}


fuku_protector::~fuku_protector()
{
}



bool fuku_protector::protect_module() {

    if (initialize_zones()) {
        pe_image_io image_io(module->get_image(), enma_io_mode_allow_expand);
        fuku_obfuscator obfuscator;

        std::vector<ob_fuku_association>   assoc_table;
        std::vector<ob_fuku_relocation>    reloc_table;
        std::vector<ob_fuku_ip_relocation> ip_reloc_table;

        obfuscator.set_arch(
            module->get_image().is_x32_image() ? ob_fuku_arch::ob_fuku_arch_x32 : ob_fuku_arch::ob_fuku_arch_x64
        );

        obfuscator.set_settings(settings);
        obfuscator.set_association_table(&assoc_table);
        obfuscator.set_relocation_table(&reloc_table);
        obfuscator.set_ip_relocation_table(&ip_reloc_table);

        uint64_t base_address = module->get_image().get_image_base();
        uint64_t dest_address = base_address +
            ALIGN_UP(
                module->get_image().get_last_section()->get_virtual_address() +
                module->get_image().get_last_section()->get_virtual_size(), module->get_image().get_section_align());

        obfuscator.set_destination_virtual_address(dest_address);
        
        module->get_image_relocations().sort();

        for (auto& code : code_placement) {
            std::vector<uint8_t> code_buffer;
            
            if (image_io.set_image_offset(code.symbol_info_rva).read(code_buffer, code.symbol_info_size) != enma_io_success) {
                return false;
            }

            std::vector<relocation_item> image_code_relocs;
            module->get_image_relocations().get_items_by_segment(image_code_relocs, code.symbol_info_rva, code.symbol_info_size);

            std::vector<ob_fuku_relocation> fuku_code_relocs;

            for (auto& code_reloc : image_code_relocs) {
                fuku_code_relocs.push_back({ code_reloc.relative_virtual_address , code_reloc.relocation_id });
            }
            
            obfuscator.push_code( code_buffer.data(), code.symbol_info_size, base_address + code.symbol_info_rva, &fuku_code_relocs );
        }

        std::vector<uint8_t> ob_code = obfuscator.obfuscate_code();



        return true;
    }

    return false;
}

bool fuku_protector::initialize_zones() {
    fuku_graph_spider code_spider(module);

    if (code_spider.decode_module()) {
        code_placement = code_spider.get_code_placement();

        if (code_placement.size()) {
            return true;
        }
    }

    return false;
}

void                  fuku_protector::sort_assoc(std::vector<ob_fuku_association>& association) {
    std::sort(association.begin(), association.end(), [](ob_fuku_association& lhs, ob_fuku_association& rhs) {
        return lhs.prev_virtual_address < rhs.prev_virtual_address;
    });
}

ob_fuku_association * fuku_protector::find_assoc(std::vector<ob_fuku_association>& association, uint32_t rva) {

    size_t left = 0;
    size_t right = association.size();
    size_t mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (association[mid].prev_virtual_address == rva) {
            return &association[mid];
        }
        else if (association[mid].prev_virtual_address > rva) {
            right = mid;
        }
        else {
            left = mid + 1;
        }
    }

    return 0;
}
#include "stdafx.h"
#include "furikuri.h"

bool ob_fuku_sensitivity::operator==(const ob_fuku_sensitivity& set) {
    return (
        this->complexity == set.complexity &&
        this->number_of_passes == set.number_of_passes &&
        this->junk_chance == set.junk_chance &&
        this->block_chance == set.block_chance &&
        this->mutate_chance == set.mutate_chance
        );
}

fuku_code_list& fuku_code_list::operator=(const fuku_code_list& set) {

    this->functions = set.functions;
    this->type      = set.type;
    this->settings  = set.settings;
    this->_module   = set._module;

    return *this;
}

furikuri::furikuri()
:main_module(0){}


furikuri::~furikuri()
{}

bool furikuri::fuku_protect(std::vector<uint8_t>& out_image) {
    bool main_has_relocations = main_module->get_image_relocations().size() != 0;

    if (shibari_linker(extended_modules, main_module).link_modules() != shibari_linker_errors::shibari_linker_ok) {
        return false;
    }

    fuku_protector protector(*main_module);

    for (auto& list : code_lists) {
        uint32_t module_offset = list._module->get_module_position().get_address_offset();

        if (module_offset) {
            for (auto& func : list.functions) {
                func.region_rva += module_offset;
            }
        }

        protector.add_profile(list.functions, list.type, list.settings);
    }

    fuku_protector_code code = protector.protect_module();

    if (code == fuku_protector_code::fuku_protector_ok) {

        shibari_builder(*main_module, main_has_relocations, out_image);

        return true;
    }

    return false;
}

bool furikuri::set_main_module(shibari_module* module, std::string module_path) {
    if (module) {
        this->main_module = module;
        return true;
    }
    return false;
}

bool furikuri::add_extended_module(shibari_module* module, std::string module_path) {
    if (module) {
       this->extended_modules.push_back(module);
       return true;
    }
    return false;
}


bool furikuri::add_code_list(fuku_protected_region& region, fuku_code_type type, shibari_module* _module, ob_fuku_sensitivity& settings) {

    bool valid_module = false;

    if (main_module == _module) {
        valid_module = true;
    }
    else {
        for (auto ext_module : extended_modules) {
            if (ext_module == _module) {
                valid_module = true;
                break;
            }
        }
    }

    if (valid_module) {
        for (auto&list : code_lists) {
            if (list._module == _module) {

                if (list.type == type) {
                    if (list.settings == settings) {
                        list.functions.push_back(region);
                        return true;
                    }
                }
            }
        }
        fuku_code_list list;
        list.type = type;
        list.settings = settings;
        list._module = _module;
        list.functions.push_back(region);

        code_lists.push_back(list);

        return true;
    }
    else {
        return false;
    }
}

void furikuri::clear_code_lists() {
    this->code_lists.clear();
}

void furikuri::clear_extended_modules() {
    this->extended_modules.clear();
}

const std::vector<fuku_code_list> & furikuri::get_code_lists() const {
    return this->code_lists;
}

std::vector<shibari_module*>& furikuri::get_extended_modules() {
    return this->extended_modules;
}
    
shibari_module* furikuri::get_main_module() {
    return this->main_module;
}
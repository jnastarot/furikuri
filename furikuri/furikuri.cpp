#include "stdafx.h"
#include "furikuri.h"

bool fuku_ob_settings::operator==(const fuku_ob_settings& set) {
    return (
        this->complexity == set.complexity &&
        this->number_of_passes == set.number_of_passes &&
        this->junk_chance == set.junk_chance &&
        this->block_chance == set.block_chance &&
        this->mutate_chance == set.mutate_chance
        );
}

bool fuku_ob_settings::is_null() const {
    return (
        this->complexity ||
        this->number_of_passes ||
        this->junk_chance ||
        this->block_chance ||
        this->mutate_chance
        );
}

fuku_code_list& fuku_code_list::operator=(const fuku_code_list& set) {

    this->functions = set.functions;
    this->type      = set.type;
    this->settings  = set.settings;
    this->target_module = set.target_module;
    this->vm_holder_module = set.vm_holder_module;
    this->vm_entry_rva = set.vm_entry_rva;
    this->virtualizer = set.virtualizer;

    return *this;
}

furikuri::furikuri()
:main_module(0){}

furikuri::~furikuri(){}


bool furikuri::fuku_protect(std::vector<uint8_t>& out_image) {
    bool main_has_relocations = main_module->get_image_relocations().size() != 0;

    if (shibari_linker(extended_modules, main_module).link_modules() != shibari_linker_errors::shibari_linker_ok) {
        return false;
    }

    fuku_protector protector(*main_module);

    for (auto& list : code_lists) {
        uint32_t module_offset = list.target_module->get_module_position().get_address_offset();

        if (module_offset) {
            for (auto& func : list.functions) {
                func.region_rva += module_offset;
            }
        }

        if (list.type == fuku_code_type::fuku_code_obfuscation) {
            protector.add_ob_profile(list.functions, list.settings);
        }
        else {

            protector.add_vm_profile(list.functions, {
                list.settings,
                list.vm_holder_module,
                list.vm_entry_rva,
                list.virtualizer          
            });
        }
        
    }

    fuku_protector_code code = protector.protect_module();

    if (code == fuku_protector_code::fuku_protector_ok) {

        shibari_builder(protector.get_target_module(), main_has_relocations, out_image);

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


bool furikuri::add_ob_code_list(fuku_protected_region region, shibari_module* target_module, fuku_ob_settings& settings) {

    bool valid_module = false;

    if (main_module == target_module) {
        valid_module = true;
    }
    else {
        for (auto ext_module : extended_modules) {
            if (ext_module == target_module) {
                valid_module = true;
                break;
            }
        }
    }

    if (valid_module) {
        for (auto&list : code_lists) {
            if (list.target_module == target_module) {

                if (list.type == fuku_code_type::fuku_code_obfuscation) {
                    if (list.settings == settings) {
                        list.functions.push_back(region);
                        return true;
                    }
                }
            }
        }

        code_lists.push_back({
            fuku_code_type::fuku_code_obfuscation,
            std::vector<fuku_protected_region>(1, region),
            settings,
            target_module,
            0, 0, 0
        });

        return true;
    }
    else {
        return false;
    }
}

bool furikuri::add_vm_code_list(fuku_protected_region region, shibari_module* target_module, fuku_vm_settings& settings) {

    bool valid_module = false;

    if (main_module == target_module) {
        valid_module = true;
    }
    else {
        for (auto ext_module : extended_modules) {
            if (ext_module == target_module) {
                valid_module = true;
                break;
            }
        }
    }

    if (valid_module) {
        for (auto&list : code_lists) {
            if (list.target_module == target_module) {

                if (list.type == fuku_code_type::fuku_code_virtualization) {
                    if (list.settings == settings.ob_settings &&
                        list.vm_holder_module == settings.vm_holder_module &&
                        list.vm_entry_rva == settings.vm_entry_rva &&
                        list.virtualizer == settings.virtualizer) {

                        list.functions.push_back(region);
                        return true;
                    }
                }
            }
        }

        code_lists.push_back({
            fuku_code_type::fuku_code_virtualization,
            std::vector<fuku_protected_region>(1, region),
            settings.ob_settings,
            target_module,

            settings.vm_holder_module,
            settings.vm_entry_rva,
            settings.virtualizer
            });

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
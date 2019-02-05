#include "stdafx.h"
#include "furikuri.h"


fuku_code_raw_list::fuku_code_raw_list() 
 :type(CODE_RAW_LIST_TYPE_NONE), target_module(0), vm_holder_module(0), vm_entry_rva(0), virtualizer(0){}

fuku_code_raw_list::fuku_code_raw_list(fuku_code_raw_list_type type, const std::vector<fuku_protected_region>& regions,
    const fuku_settings_obfuscation& settings, shibari_module*  target_module,
    shibari_module*  vm_holder_module, uint32_t vm_entry_rva, fuku_virtualizer * virtualizer)
    : type(type), functions(regions), settings(settings), target_module(target_module), vm_holder_module(vm_holder_module),
    vm_entry_rva(vm_entry_rva), virtualizer(virtualizer){}

fuku_code_raw_list::fuku_code_raw_list(const fuku_code_raw_list& list) {
    operator=(list);
}

fuku_code_raw_list::~fuku_code_raw_list() {

}

fuku_code_raw_list& fuku_code_raw_list::operator=(const fuku_code_raw_list& list) {
    this->functions     = list.functions;
    this->type          = list.type;
    this->settings      = list.settings;
    this->target_module = list.target_module;
    this->vm_holder_module = list.vm_holder_module;
    this->vm_entry_rva  = list.vm_entry_rva;
    this->virtualizer   = list.virtualizer;

    return *this;
}

void fuku_code_raw_list::set_type(fuku_code_raw_list_type type) {
    this->type = type;
}

void fuku_code_raw_list::set_functions(const std::vector<fuku_protected_region>& functions) {
    this->functions = functions;
}
void fuku_code_raw_list::set_settings(const fuku_settings_obfuscation& settings) {
    this->settings = settings;
}
void fuku_code_raw_list::set_target_module(shibari_module* _module) {
    this->target_module = _module;
}
void fuku_code_raw_list::set_vm_holder_module(shibari_module* _module) {
    this->vm_holder_module = _module;
}
void fuku_code_raw_list::set_vm_entry_rva(uint32_t entry_rva) {
    this->vm_entry_rva = entry_rva;
}
void fuku_code_raw_list::set_virtualizer(fuku_virtualizer * virt) {
    this->virtualizer = virt;
}


std::vector<fuku_protected_region>& fuku_code_raw_list::get_functions() {
    return this->functions;
}
fuku_settings_obfuscation& fuku_code_raw_list::get_settings() {
    return this->settings;
}
shibari_module*  fuku_code_raw_list::get_target_module() {
    return this->target_module;
}
shibari_module*  fuku_code_raw_list::get_vm_holder_module() {
    return this->vm_holder_module;
}
fuku_virtualizer * fuku_code_raw_list::get_virtualizer() {
    return this->virtualizer;
}

const fuku_code_raw_list_type fuku_code_raw_list::get_type() const {
    return this->type;
}
const std::vector<fuku_protected_region>& fuku_code_raw_list::get_functions() const {
    return this->functions;
}
const fuku_settings_obfuscation& fuku_code_raw_list::get_settings() const {
    return this->settings;
}
const shibari_module*  fuku_code_raw_list::get_target_module() const {
    return this->target_module;
}
const shibari_module*  fuku_code_raw_list::get_vm_holder_module() const {
    return this->vm_holder_module;
}
const uint32_t fuku_code_raw_list::get_vm_entry_rva() const {
    return this->vm_entry_rva;
}
const fuku_virtualizer * fuku_code_raw_list::get_virtualizer() const {
    return this->virtualizer;
}

furikuri::furikuri()
:main_module(0){}

furikuri::~furikuri(){}


bool furikuri::fuku_protect(std::vector<uint8_t>& out_image) {
    bool main_has_relocations = main_module->get_image_relocations().size() != 0;

    shibari_linker_errors linker_result = shibari_linker(extended_modules, main_module).link_modules();

    if (linker_result != shibari_linker_errors::shibari_linker_ok) {
        return false;
    }

    fuku_protect_mgr protector(*main_module);

    for (auto& list : code_raw_lists) {
        uint32_t module_offset = list.get_target_module()->get_module_position().get_address_offset();

        if (module_offset) {
            for (auto& func : list.get_functions()) {
                func.region_rva += module_offset;
            }
        }

        if (list.get_type() == CODE_RAW_LIST_TYPE_OBFUSCATION) {
            protector.add_ob_profile(list.get_functions(), list.get_settings());
        }
        else {

            protector.add_vm_profile(list.get_functions(), fuku_settings_virtualization(
                list.get_settings(),
                list.get_vm_holder_module(),
                list.get_vm_entry_rva(),
                list.get_virtualizer()
            ));
        }
        
    }

    fuku_protect_mgr_result code = protector.protect_module();

    if (code == fuku_protect_mgr_result::fuku_protect_ok) {

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


bool furikuri::add_ob_code_list(fuku_protected_region region, shibari_module* target_module, fuku_settings_obfuscation& settings) {

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
        for (auto&list : code_raw_lists) {
            if (list.get_target_module() == target_module) {

                if (list.get_type() == CODE_RAW_LIST_TYPE_OBFUSCATION) {
                    if (list.get_settings() == settings) {
                        list.get_functions().push_back(region);
                        return true;
                    }
                }
            }
        }

        code_raw_lists.push_back(fuku_code_raw_list(
            CODE_RAW_LIST_TYPE_OBFUSCATION,
            std::vector<fuku_protected_region>(1, region),
            settings,
            target_module,
            0, 0, 0
        ));

        return true;
    }
    else {
        return false;
    }
}

bool furikuri::add_vm_code_list(fuku_protected_region region, shibari_module* target_module, fuku_settings_virtualization& settings) {

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
        for (auto& list : code_raw_lists) {
            if (list.get_target_module() == target_module) {

                if (list.get_type() == CODE_RAW_LIST_TYPE_VIRTUALIZATION) {
                    if (list.get_settings() == settings.get_obfuscation_settings() &&
                        list.get_vm_holder_module() == settings.get_vm_holder_module() &&
                        list.get_vm_entry_rva() == settings.get_vm_entry_rva() &&
                        list.get_virtualizer() == settings.get_virtualizer() ) {

                        list.get_functions().push_back(region);
                        return true;
                    }
                }
            }
        }

        code_raw_lists.push_back(fuku_code_raw_list(
            CODE_RAW_LIST_TYPE_VIRTUALIZATION,
            std::vector<fuku_protected_region>(1, region),
            settings.get_obfuscation_settings(),
            target_module,

            settings.get_vm_holder_module(),
            settings.get_vm_entry_rva(),
            settings.get_virtualizer()
            ));

        return true;
    }
    else {
        return false;
    }
}

void furikuri::clear_code_lists() {
    this->code_raw_lists.clear();
}

void furikuri::clear_extended_modules() {
    this->extended_modules.clear();
}

const std::vector<fuku_code_raw_list> & furikuri::get_code_raw_lists() const {
    return this->code_raw_lists;
}

std::vector<shibari_module*>& furikuri::get_extended_modules() {
    return this->extended_modules;
}
    
shibari_module* furikuri::get_main_module() {
    return this->main_module;
}
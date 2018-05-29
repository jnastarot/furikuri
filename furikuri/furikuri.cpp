#include "stdafx.h"
#include "furikuri.h"


furikuri::furikuri()
:main_module(0){}


furikuri::~furikuri()
{}

bool furikuri::fuku_protect(const ob_fuku_sensitivity& settings,std::vector<uint8_t>& out_image, fuku_code_list *_code_list) {
    bool main_has_relocations = main_module->get_image_relocations().size() != 0;

    if (shibari_linker(extended_modules, main_module).link_modules() != shibari_linker_errors::shibari_linker_ok) {
        return false;
    }

    fuku_code_list code_list;

    if (_code_list) {
        code_list = *_code_list;
    }
    else {
        for (auto& code_sym : main_module->get_code_symbols()) {
            code_list.func_starts.push_back(code_sym.symbol_info_rva);
            code_list.code_placement.push_back(code_sym);
        }
    }

    if (code_list.code_placement.size()) {
        if (fuku_protector(main_module, settings, code_list).protect_module()) {

            shibari_builder(*main_module, main_has_relocations, out_image);

            return true;
        }
    }
    else {
        shibari_builder(*main_module, main_has_relocations, out_image);

        return true;
    }

    return false;
}

bool furikuri::set_main_module(shibari_module* module, std::string module_path) {
    if (module) {
        if (fuku_module_decoder(module, module_path).decode_module()) {
            this->main_module = module;

            return true;
        }
    }
    return false;
}

bool furikuri::add_extended_module(shibari_module* module, std::string module_path) {
    if (module) {
        if (fuku_module_decoder(module, module_path).decode_module()) {
            this->extended_modules.push_back(module);

            return true;
        }
    }
    return false;
}

std::vector<shibari_module*>& furikuri::get_extended_modules() {
    return this->extended_modules;
}
    
shibari_module* furikuri::get_main_module() {
    return this->main_module;
}
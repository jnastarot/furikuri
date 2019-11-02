#include "stdafx.h"
#include "furikuri.h"



furikuri_protection_entry::furikuri_protection_entry() 
 :type(FURIKURI_PROTECTION_TYPE_NONE), virtualizer(0){}

furikuri_protection_entry::furikuri_protection_entry(furikuri_protection_type type, const std::vector<fuku_protected_region>& regions,
    const fuku_settings_obfuscation& settings, fuku_virtualizer* virtualizer)
    : type(type), functions(regions), settings(settings), virtualizer(virtualizer){}

furikuri_protection_entry::furikuri_protection_entry(const furikuri_protection_entry& list) {
    operator=(list);
}

furikuri_protection_entry::~furikuri_protection_entry() {

}

furikuri_protection_entry& furikuri_protection_entry::operator=(const furikuri_protection_entry& list) {
    this->functions     = list.functions;
    this->type          = list.type;
    this->settings      = list.settings;
    this->virtualizer   = list.virtualizer;

    return *this;
}

void furikuri_protection_entry::set_type(furikuri_protection_type type) {
    this->type = type;
}

void furikuri_protection_entry::set_functions(const std::vector<fuku_protected_region>& functions) {
    this->functions = functions;
}
void furikuri_protection_entry::set_settings(const fuku_settings_obfuscation& settings) {
    this->settings = settings;
}
void furikuri_protection_entry::set_virtualizer(fuku_virtualizer * virt) {
    this->virtualizer = virt;
}


std::vector<fuku_protected_region>& furikuri_protection_entry::get_functions() {
    return this->functions;
}
fuku_settings_obfuscation& furikuri_protection_entry::get_settings() {
    return this->settings;
}
fuku_virtualizer * furikuri_protection_entry::get_virtualizer() {
    return this->virtualizer;
}

const furikuri_protection_type furikuri_protection_entry::get_type() const {
    return this->type;
}
const std::vector<fuku_protected_region>& furikuri_protection_entry::get_functions() const {
    return this->functions;
}
const fuku_settings_obfuscation& furikuri_protection_entry::get_settings() const {
    return this->settings;
}
const fuku_virtualizer * furikuri_protection_entry::get_virtualizer() const {
    return this->virtualizer;
}

furikuri::furikuri()
:_image(0){}

furikuri::~furikuri(){

    if (_image) {
        delete _image; _image = 0;
    }
}


bool furikuri::fuku_protect(std::vector<uint8_t>& out_image) {

    bool main_has_relocations = _image->get_relocations().size() != 0;

    fuku_protect_mgr protect_manager;

    protect_manager.get_settings().set_target_module(*_image);
    protect_manager.get_settings().set_module_used_relocations(main_has_relocations);

    for (auto& list : protect_list) {

        if (list.get_type() == FURIKURI_PROTECTION_TYPE_OBFUSCATION) {
            protect_manager.add_ob_profile(list.get_functions(), list.get_settings());
        }
        else {

            protect_manager.add_vm_profile(list.get_functions(), fuku_settings_virtualization(
                list.get_settings(),
                list.get_virtualizer()
            ));
        }
        
    }

    fuku_protect_mgr_result code = protect_manager.step_to_stage(fuku_protect_stage_full);

    if (code == fuku_protect_ok) {

        build_pe_image_full(protect_manager.get_settings().get_target_module(),
            PE_IMAGE_BUILD_ALL_EXTENDED_SECTIONS | (PE_IMAGE_BUILD_ALL_DIRECTORIES & ~(PE_IMAGE_BUILD_DIR_IMPORT)), out_image);

        return true;
    }

    return false;
}

bool furikuri::fuku_protect(const fuku_settings_mgr& mgr_settings, std::vector<uint8_t>& out_image) {

    fuku_protect_mgr protect_manager;

    protect_manager_load_snapshot(protect_manager, mgr_settings);

    fuku_protect_mgr_result code = protect_manager.step_to_stage(fuku_protect_stage_full);

    if (code == fuku_protect_ok) {

        build_pe_image_full(protect_manager.get_settings().get_target_module(),
            PE_IMAGE_BUILD_ALL_EXTENDED_SECTIONS | (PE_IMAGE_BUILD_ALL_DIRECTORIES & ~(PE_IMAGE_BUILD_DIR_IMPORT)), out_image);

        return true;
    }

    return false;
}

bool furikuri::create_snapshot(fuku_settings_mgr& mgr_settings, fuku_protect_stage stage) {

    bool main_has_relocations = _image->get_relocations().size() != 0;

    mgr_settings.set_target_module(*_image);
    mgr_settings.set_module_used_relocations(main_has_relocations);

    for (auto& list : protect_list) {

        if (list.get_type() == FURIKURI_PROTECTION_TYPE_OBFUSCATION) {
            mgr_settings.add_ob_profile(list.get_functions(), list.get_settings());
        }
        else {

            mgr_settings.add_vm_profile(list.get_functions(), fuku_settings_virtualization(
                list.get_settings(),
                list.get_virtualizer()
            ));
        }

    }

    return protect_manager_create_stage_snapshot(mgr_settings, stage);
}

bool furikuri::set_image_protect(const pe_image& _module) {

    if (this->_image) {
        delete this->_image; this->_image = 0;
    }

    this->_image = new pe_image_full(_module);

    pe_placement placement;
  //  get_directories_placement(this->_image->get_image(), placement, &this->_image->get_bound_imports());

    placement.clear();
    get_placement_export_directory(this->_image->get_image(), placement);
    get_placement_resources_directory(this->_image->get_image(), placement);
    get_placement_exceptions_directory(this->_image->get_image(), placement);
    get_placement_security_directory(this->_image->get_image(), placement);
    get_placement_relocation_directory(this->_image->get_image(), placement);
    get_placement_debug_directory(this->_image->get_image(), placement);
    get_placement_tls_directory(this->_image->get_image(), placement);
    get_placement_load_config_directory(this->_image->get_image(), placement);
    get_placement_bound_import_directory(this->_image->get_image(), placement);
    get_placement_delay_import_directory(this->_image->get_image(), placement, this->_image->get_bound_imports());

    pe_erase_placement(this->_image->get_image(), placement, &this->_image->get_relocations(), true);

    return true;
}

bool furikuri::set_image_protect(const std::string& module_path) {

    if (this->_image) {
        delete this->_image; this->_image = 0;
    }

    pe_image new_image(module_path);

    if (new_image.get_image_status() == pe_image_status::pe_image_status_ok) {

        this->_image = new pe_image_full(new_image);

        pe_placement placement;
        get_directories_placement(this->_image->get_image(), placement, &this->_image->get_bound_imports());
        pe_erase_placement(this->_image->get_image(), placement, &this->_image->get_relocations(), true);

        return true;
    }

    return false;
}


bool furikuri::add_ob_code_list(fuku_protected_region region, fuku_settings_obfuscation& settings) {


    for (auto& list : protect_list) {

        if (list.get_type() == FURIKURI_PROTECTION_TYPE_OBFUSCATION) {
            if (list.get_settings() == settings) {
                list.get_functions().push_back(region);

                return true;
            }
        }
    }

    protect_list.push_back(furikuri_protection_entry(
        FURIKURI_PROTECTION_TYPE_OBFUSCATION,
        std::vector<fuku_protected_region>(1, region),
        settings,
        0
    ));

    return true;

}

bool furikuri::add_vm_code_list(fuku_protected_region region, fuku_settings_virtualization& settings) {

    for (auto& list : protect_list) {

        if (list.get_type() == FURIKURI_PROTECTION_TYPE_VIRTUALIZATION) {
            if (list.get_settings() == settings.get_obfuscation_settings() &&
                list.get_virtualizer() == settings.get_virtualizer()) {

                list.get_functions().push_back(region);
                return true;
            }
        }
    }

    protect_list.push_back(furikuri_protection_entry(
        FURIKURI_PROTECTION_TYPE_VIRTUALIZATION,
        std::vector<fuku_protected_region>(1, region),
        settings.get_obfuscation_settings(),
        settings.get_virtualizer()
    ));

    return true;

}

void furikuri::clear_protect_list() {
    this->protect_list.clear();
}

const std::vector<furikuri_protection_entry> & furikuri::get_protect_list() const {
    return this->protect_list;
}
 
pe_image_full* furikuri::get_image() {
    return this->_image;
}
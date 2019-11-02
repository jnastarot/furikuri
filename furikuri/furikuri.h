#pragma once

using namespace fukutasm;

class fuku_code_analyzer;
class fuku_code_profiler;
class fuku_mutation;
class fuku_virtualizer;
class fuku_obfuscator;



//#include "psyche_storage.h"
#include "fuku_settings_obfuscation.h"
#include "fuku_settings_virtualization.h"
#include "fuku_obfuscator.h"
#include "fuku_virtualizer_imp.h"
#include "fuku_protect_mgr.h"



enum furikuri_protection_type {
    FURIKURI_PROTECTION_TYPE_NONE,
    FURIKURI_PROTECTION_TYPE_OBFUSCATION,
    FURIKURI_PROTECTION_TYPE_VIRTUALIZATION,
};

class furikuri_protection_entry {
    furikuri_protection_type type;

    std::vector<fuku_protected_region> functions;

    fuku_settings_obfuscation settings;

    fuku_virtualizer* virtualizer;

public:
    furikuri_protection_entry();
    furikuri_protection_entry(furikuri_protection_type type, const std::vector<fuku_protected_region>& regions,
        const fuku_settings_obfuscation& settings, fuku_virtualizer* virtualizer);

    furikuri_protection_entry(const furikuri_protection_entry& list);
    ~furikuri_protection_entry();

    furikuri_protection_entry& operator=(const furikuri_protection_entry& list);
public:
    void set_type(furikuri_protection_type type);
    void set_functions(const std::vector<fuku_protected_region>& functions);
    void set_settings(const fuku_settings_obfuscation& settings);
    void set_virtualizer(fuku_virtualizer* virt);

public:
    std::vector<fuku_protected_region>& get_functions();
    fuku_settings_obfuscation& get_settings();
    fuku_virtualizer* get_virtualizer();

public:
    const furikuri_protection_type get_type() const;
    const std::vector<fuku_protected_region>& get_functions() const;
    const fuku_settings_obfuscation& get_settings() const;
    const fuku_virtualizer* get_virtualizer() const;

};

class furikuri {

    pe_image_full * _image;
    std::vector<furikuri_protection_entry> protect_list;

public:
    furikuri();
    ~furikuri();

    bool fuku_protect(std::vector<uint8_t>& out_image); //for custom settings
    bool fuku_protect(const fuku_settings_mgr& mgr_settings, std::vector<uint8_t>& out_image); //for snapshot settings

    bool create_snapshot(fuku_settings_mgr& mgr_settings, fuku_protect_stage stage);

public:
    bool set_image_protect(const pe_image& _module);
    bool set_image_protect(const std::string& module_path);

    bool add_ob_code_list(fuku_protected_region region, fuku_settings_obfuscation& settings);
    bool add_vm_code_list(fuku_protected_region region, fuku_settings_virtualization& settings);

    void clear_protect_list();

public:
    const std::vector<furikuri_protection_entry>& get_protect_list() const;
    pe_image_full* get_image();

};


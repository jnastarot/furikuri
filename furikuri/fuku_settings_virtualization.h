#pragma once

class fuku_virtualization_environment {
    uint32_t  virtual_machine_entry;
    fuku_virtualizer *  virtualizer;

public:
    fuku_virtualization_environment();
    fuku_virtualization_environment(uint32_t virtual_machine_entry, fuku_virtualizer *  virtualizer);
    fuku_virtualization_environment(const fuku_virtualization_environment& env);
    fuku_virtualization_environment& operator=(const fuku_virtualization_environment& env);

    ~fuku_virtualization_environment();

    bool operator==(const fuku_virtualization_environment& env) const;
    bool operator<(const fuku_virtualization_environment& rhs) const;

public:
    void set_virtual_machine_entry(uint32_t entry);
    void set_virtualizer(fuku_virtualizer * virt);

public:
    uint32_t  get_virtual_machine_entry() const;
    const fuku_virtualizer *  get_virtualizer() const;
    fuku_virtualizer *  get_virtualizer();
};

class fuku_settings_virtualization {
    fuku_settings_obfuscation ob_settings;

    shibari_module* vm_holder_module;//vm holder
    uint32_t        vm_entry_rva;    //vm offset

    fuku_virtualizer * virtualizer;

public:
    fuku_settings_virtualization();
    fuku_settings_virtualization(const fuku_settings_obfuscation& ob_settings, shibari_module* vm_holder_module, 
        uint32_t vm_entry_rva,fuku_virtualizer * virtualizer);

    fuku_settings_virtualization(const fuku_settings_virtualization& virt_set);
    ~fuku_settings_virtualization();

    fuku_settings_virtualization& operator=(const fuku_settings_virtualization& virt_set);
public:
    void set_obfuscation_settings(const fuku_settings_obfuscation& settings);
    void set_vm_holder_module(shibari_module* _module);
    void set_vm_entry_rva(uint32_t rva);
    void set_virtualizer(fuku_virtualizer * virt);

public:
    const fuku_settings_obfuscation& get_obfuscation_settings() const;
    const shibari_module* get_vm_holder_module() const;
    shibari_module* get_vm_holder_module();
    uint32_t  get_vm_entry_rva() const;
    const fuku_virtualizer * get_virtualizer() const;
    fuku_virtualizer * get_virtualizer();
};


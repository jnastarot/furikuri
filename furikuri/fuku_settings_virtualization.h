#pragma once

class fuku_virtualization_environment {
    fuku_virtualizer *  virtualizer;

public:
    fuku_virtualization_environment();
    fuku_virtualization_environment(fuku_virtualizer *  virtualizer);
    fuku_virtualization_environment(const fuku_virtualization_environment& env);
    fuku_virtualization_environment& operator=(const fuku_virtualization_environment& env);

    ~fuku_virtualization_environment();

    bool operator==(const fuku_virtualization_environment& env) const;
    bool operator<(const fuku_virtualization_environment& rhs) const;

public:
    void set_virtualizer(fuku_virtualizer * virt);

public:
    const fuku_virtualizer *  get_virtualizer() const;
    fuku_virtualizer *  get_virtualizer();

};

class fuku_settings_virtualization {
    fuku_settings_obfuscation ob_settings;
    fuku_virtualizer * virtualizer;

public:
    fuku_settings_virtualization();
    fuku_settings_virtualization(const fuku_settings_obfuscation& ob_settings, fuku_virtualizer * virtualizer);
    fuku_settings_virtualization(const fuku_settings_virtualization& virt_set);
    ~fuku_settings_virtualization();

    fuku_settings_virtualization& operator=(const fuku_settings_virtualization& virt_set);
public:
    void set_obfuscation_settings(const fuku_settings_obfuscation& settings);
    void set_virtualizer(fuku_virtualizer * virt);

public:
    const fuku_settings_obfuscation& get_obfuscation_settings() const;
    const fuku_virtualizer * get_virtualizer() const;
    fuku_virtualizer * get_virtualizer();
};


#include "stdafx.h"
#include "fuku_settings_virtualization.h"


fuku_virtualization_environment::fuku_virtualization_environment() 
    :virtualizer(0) {}

fuku_virtualization_environment::fuku_virtualization_environment(fuku_virtualizer *  virtualizer)
    : virtualizer(virtualizer) {}

fuku_virtualization_environment::fuku_virtualization_environment(const fuku_virtualization_environment& env) {
    operator=(env);
}

fuku_virtualization_environment::~fuku_virtualization_environment() {

}

fuku_virtualization_environment& fuku_virtualization_environment::operator=(const fuku_virtualization_environment& env) {
    this->virtualizer = env.virtualizer;

    return *this;
}

bool fuku_virtualization_environment::operator==(const fuku_virtualization_environment& env) const {
    return this->virtualizer == env.virtualizer;
}

bool fuku_virtualization_environment::operator<(const fuku_virtualization_environment& rhs) const {
    return this->virtualizer < rhs.virtualizer;
}


void fuku_virtualization_environment::set_virtualizer(fuku_virtualizer * virt) {
    this->virtualizer = virt;
}

const fuku_virtualizer *  fuku_virtualization_environment::get_virtualizer() const {
    return this->virtualizer;
}

fuku_virtualizer *  fuku_virtualization_environment::get_virtualizer() {
    return this->virtualizer;
}

fuku_settings_virtualization::fuku_settings_virtualization() 
 : virtualizer(0){}

fuku_settings_virtualization::fuku_settings_virtualization(const fuku_settings_obfuscation& ob_settings, fuku_virtualizer* virtualizer)
    : ob_settings(ob_settings), virtualizer(virtualizer) {}

fuku_settings_virtualization::fuku_settings_virtualization(const fuku_settings_virtualization& virt_set) {
    operator=(virt_set);
}

fuku_settings_virtualization::~fuku_settings_virtualization() {

}

fuku_settings_virtualization& fuku_settings_virtualization::operator=(const fuku_settings_virtualization& virt_set) {
    this->ob_settings = virt_set.ob_settings;
    this->virtualizer = virt_set.virtualizer;

    return *this;
}
void fuku_settings_virtualization::set_obfuscation_settings(const fuku_settings_obfuscation& settings) {
    this->ob_settings = settings;
}
void fuku_settings_virtualization::set_virtualizer(fuku_virtualizer * virt) {
    this->virtualizer = virt;
}

const fuku_settings_obfuscation& fuku_settings_virtualization::get_obfuscation_settings() const {
    return this->ob_settings;
}

const fuku_virtualizer * fuku_settings_virtualization::get_virtualizer() const {
    return this->virtualizer;
}

fuku_virtualizer * fuku_settings_virtualization::get_virtualizer() {
    return this->virtualizer;
}
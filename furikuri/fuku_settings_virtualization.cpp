#include "stdafx.h"
#include "fuku_settings_virtualization.h"


fuku_virtualization_environment::fuku_virtualization_environment() 
    :virtualizer(0), virtual_machine_entry(0) {}

fuku_virtualization_environment::fuku_virtualization_environment(uint32_t virtual_machine_entry, fuku_virtualizer *  virtualizer)
    : virtual_machine_entry(virtual_machine_entry), virtualizer(virtualizer) {}

fuku_virtualization_environment::fuku_virtualization_environment(const fuku_virtualization_environment& env) {
    operator=(env);
}

fuku_virtualization_environment::~fuku_virtualization_environment() {

}

fuku_virtualization_environment& fuku_virtualization_environment::operator=(const fuku_virtualization_environment& env) {
    this->virtualizer = env.virtualizer;
    this->virtual_machine_entry = env.virtual_machine_entry;

    return *this;
}

bool fuku_virtualization_environment::operator==(const fuku_virtualization_environment& env) const {
    return this->virtualizer == env.virtualizer && this->virtual_machine_entry == env.virtual_machine_entry;
}

bool fuku_virtualization_environment::operator<(const fuku_virtualization_environment& rhs) const {
    return this->virtualizer < rhs.virtualizer && this->virtual_machine_entry < rhs.virtual_machine_entry;
}


void fuku_virtualization_environment::set_virtual_machine_entry(uint32_t entry) {
    this->virtual_machine_entry = entry;
}

void fuku_virtualization_environment::set_virtualizer(fuku_virtualizer * virt) {
    this->virtualizer = virt;
}

uint32_t  fuku_virtualization_environment::get_virtual_machine_entry() const {
    return this->virtual_machine_entry;
}

const fuku_virtualizer *  fuku_virtualization_environment::get_virtualizer() const {
    return this->virtualizer;
}

fuku_virtualizer *  fuku_virtualization_environment::get_virtualizer() {
    return this->virtualizer;
}

fuku_settings_virtualization::fuku_settings_virtualization() 
 :vm_holder_module(0), vm_entry_rva(0), virtualizer(0){}

fuku_settings_virtualization::fuku_settings_virtualization(const fuku_settings_obfuscation& ob_settings, shibari_module* vm_holder_module,
    uint32_t vm_entry_rva, fuku_virtualizer * virtualizer)
    : ob_settings(ob_settings), vm_holder_module(vm_holder_module), 
    vm_entry_rva(vm_entry_rva), virtualizer(virtualizer) {}

fuku_settings_virtualization::fuku_settings_virtualization(const fuku_settings_virtualization& virt_set) {
    operator=(virt_set);
}

fuku_settings_virtualization::~fuku_settings_virtualization() {

}

fuku_settings_virtualization& fuku_settings_virtualization::operator=(const fuku_settings_virtualization& virt_set) {
    this->ob_settings = virt_set.ob_settings;
    this->vm_holder_module = virt_set.vm_holder_module;
    this->vm_entry_rva = virt_set.vm_entry_rva;
    this->virtualizer = virt_set.virtualizer;

    return *this;
}
void fuku_settings_virtualization::set_obfuscation_settings(const fuku_settings_obfuscation& settings) {
    this->ob_settings = settings;
}
void fuku_settings_virtualization::set_vm_holder_module(shibari_module* _module) {
    this->vm_holder_module = _module;
}
void fuku_settings_virtualization::set_vm_entry_rva(uint32_t rva) {
    this->vm_entry_rva = rva;
}
void fuku_settings_virtualization::set_virtualizer(fuku_virtualizer * virt) {
    this->virtualizer = virt;
}

const fuku_settings_obfuscation& fuku_settings_virtualization::get_obfuscation_settings() const {
    return this->ob_settings;
}
const shibari_module* fuku_settings_virtualization::get_vm_holder_module() const {
    return this->vm_holder_module;
}
shibari_module* fuku_settings_virtualization::get_vm_holder_module() {
    return this->vm_holder_module;
}
uint32_t  fuku_settings_virtualization::get_vm_entry_rva() const {
    return this->vm_entry_rva;
}
const fuku_virtualizer * fuku_settings_virtualization::get_virtualizer() const {
    return this->virtualizer;
}

fuku_virtualizer * fuku_settings_virtualization::get_virtualizer() {
    return this->virtualizer;
}
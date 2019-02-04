#include "stdafx.h"
#include "fuku_settings_virtualization.h"


fuku_virtualization_environment::fuku_virtualization_environment() 
    :virtualizer(0), virtual_machine_entry(0) {}

fuku_virtualization_environment::fuku_virtualization_environment(uint32_t virtual_machine_entry, fuku_virtualizer *  virtualizer)
    : virtual_machine_entry(virtual_machine_entry), virtualizer(virtualizer) {}

fuku_virtualization_environment::fuku_virtualization_environment(const fuku_virtualization_environment& env) {
    operator=(env);
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

fuku_settings_virtualization::fuku_settings_virtualization() {

}

fuku_settings_virtualization::~fuku_settings_virtualization() {

}
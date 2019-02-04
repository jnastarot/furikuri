#include "stdafx.h"
#include "fuku_settings_obfuscation.h"


fuku_settings_obfuscation::fuku_settings_obfuscation() 
    :complexity(0), number_of_passes(0), junk_chance(0), block_chance(0),
    mutate_chance(0), asm_cfg(0) {}

fuku_settings_obfuscation::fuku_settings_obfuscation(unsigned int complexity, unsigned int number_of_passes,
    float junk_chance, float block_chance, float mutate_chance, uint8_t asm_cfg) 
    :complexity(complexity), number_of_passes(number_of_passes), junk_chance(junk_chance), block_chance(block_chance),
    mutate_chance(mutate_chance), asm_cfg(asm_cfg) {}

fuku_settings_obfuscation::fuku_settings_obfuscation(const fuku_settings_obfuscation& obf_set) {
    operator=(obf_set);
}

fuku_settings_obfuscation::~fuku_settings_obfuscation() {

}
fuku_settings_obfuscation& fuku_settings_obfuscation::operator=(const fuku_settings_obfuscation& obf_set) {
    this->complexity        = obf_set.complexity;
    this->number_of_passes  = obf_set.number_of_passes;
    this->junk_chance       = obf_set.junk_chance;
    this->block_chance      = obf_set.block_chance;
    this->mutate_chance     = obf_set.mutate_chance;
    this->asm_cfg           = obf_set.asm_cfg;

    return *this;
}

bool fuku_settings_obfuscation::operator==(const fuku_settings_obfuscation& obf_set) const {
    return (
        this->complexity == obf_set.complexity && this->number_of_passes == obf_set.number_of_passes &&
        this->junk_chance == obf_set.junk_chance && this->block_chance == obf_set.block_chance &&
        this->mutate_chance == obf_set.mutate_chance && this->asm_cfg == obf_set.asm_cfg);
}

void fuku_settings_obfuscation::set_complexity(unsigned int complexity) {
    this->complexity = complexity;
}
void fuku_settings_obfuscation::set_number_of_passes(unsigned int passes) {
    this->number_of_passes = passes;
}
void fuku_settings_obfuscation::set_junk_chance(float chance) {
    this->junk_chance = chance;
}
void fuku_settings_obfuscation::set_block_chance(float chance) {
    this->block_chance = chance;
}
void fuku_settings_obfuscation::set_mutate_chance(float chance) {
    this->mutate_chance = chance;
}
void fuku_settings_obfuscation::set_asm_cfg(uint8_t flags) {
    this->asm_cfg = flags;
}

unsigned int fuku_settings_obfuscation::get_complexity() const {
    return this->complexity;
}
unsigned int fuku_settings_obfuscation::get_number_of_passes() const {
    return this->number_of_passes;
}
float   fuku_settings_obfuscation::get_junk_chance() const {
    return this->junk_chance;
}
float   fuku_settings_obfuscation::get_block_chance() const {
    return this->block_chance;
}
float   fuku_settings_obfuscation::get_mutate_chance() const {
    return this->mutate_chance;
}
uint8_t fuku_settings_obfuscation::get_asm_cfg() const {
    return this->asm_cfg;
}

bool fuku_settings_obfuscation::is_null() const {
    return (
        this->complexity ||
        this->number_of_passes ||
        this->junk_chance ||
        this->block_chance ||
        this->mutate_chance ||
        this->asm_cfg
        );
}
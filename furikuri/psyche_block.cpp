#include "stdafx.h"
#include "psyche_block.h"

psyche_block::psyche_block(uint8_t arch)
    :arch(arch), flags(0){
}

psyche_block::psyche_block(const psyche_block& block) {
    this->operator=(block);
}

psyche_block::psyche_block(uint8_t arch, uint64_t flags,
    size_t block_rva, size_t label_idx)
    :arch(arch), flags(flags), block_rva(block_rva), label_idx(label_idx) {}


psyche_block::~psyche_block() {

}


psyche_block& psyche_block::operator=(const psyche_block& block) {

    this->arch = block.arch;
    this->flags = block.flags;

    this->block_rva = block.block_rva;
    this->label_idx = block.label_idx;

    this->instructions = block.instructions;
    this->properties = block.properties;

    return *this;
}

void psyche_block::set_arch(uint8_t arch) {
    this->arch = arch;
}

void psyche_block::set_flags(uint64_t flags) {
    this->flags = flags;
}

void psyche_block::set_block_rva(uint32_t rva) {
    this->block_rva = rva;
}

void psyche_block::set_label_idx(size_t label) {
    this->label_idx = label;
}

void psyche_block::set_instructions(const psy_instructions& instructions) {
    this->instructions = instructions;
}

void psyche_block::set_properties(const psy_block_props& properties) {
    this->properties = properties;
}

void psyche_block::add_line(fuku_inst* line) {
    instructions[line] = commands_table();
}

uint8_t psyche_block::get_arch() const {
    return this->arch;
}

uint64_t psyche_block::get_flags() const {
    return this->flags;
}

uint32_t psyche_block::get_block_rva() const {
    return this->block_rva;
}

size_t psyche_block::get_label_idx() const {
    return this->label_idx;
}

psy_instructions& psyche_block::get_instructions() {
    return this->instructions;
}

const psy_instructions& psyche_block::get_instructions() const {
    return this->instructions;
}

psy_block_props& psyche_block::get_properties() {
    return this->properties;
}

const psy_block_props& psyche_block::get_properties() const {
    return this->properties;
}

#include "stdafx.h"
#include "fuku_instruction.h"

typedef cs_struct cs_struct;
extern uint8_t *X86_get_op_access(cs_struct *h, unsigned int id, uint64_t *eflags);

fuku_instruction::fuku_instruction()
    :id(-1), op_length(0), op_pref_size(0), op_code({ 0 }),
    source_virtual_address(-1), virtual_address(-1),
    label_idx(-1), link_label_idx(-1), 
    code_relocation_1_idx(-1), code_relocation_2_idx(-1), code_rip_relocation_idx(-1),
    instruction_flags(0), eflags(0) {}

fuku_instruction::fuku_instruction(const fuku_instruction& line) {
    this->operator=(line);
}


fuku_instruction::~fuku_instruction(){

}

fuku_instruction& fuku_instruction::operator=(const fuku_instruction& line) {

    memcpy(this->op_code, line.op_code, line.op_length);
    this->id = line.id; 

    this->op_length = line.op_length;
    this->op_pref_size = line.op_pref_size;
    this->source_virtual_address = line.source_virtual_address;
    this->virtual_address = line.virtual_address;
    this->label_idx = line.label_idx;
    this->link_label_idx = line.link_label_idx;
    this->code_relocation_1_idx = line.code_relocation_1_idx;
    this->code_relocation_2_idx = line.code_relocation_2_idx;
    this->code_rip_relocation_idx = line.code_rip_relocation_idx;
    this->instruction_flags = line.instruction_flags;
    this->eflags = line.eflags;

    return *this;
}

uint8_t fuku_instruction::get_prefixes_number() {
    uint32_t i = 0;
    for (i = 0;
        i < op_length &&
        (op_code[i] == 0xF0 ||  //lock
            op_code[i] == 0xF3 || //repe
            op_code[i] == 0xF2 || //repne
            op_code[i] == 0x2E || //cs
            op_code[i] == 0x36 || //ss
            op_code[i] == 0x3E || //ds
            op_code[i] == 0x26 || //es
            op_code[i] == 0x64 || //fs
            op_code[i] == 0x65) //gs
        ;
    i++) {
    }
    return i;
}



fuku_instruction & fuku_instruction::set_id(uint16_t id) {
    this->id = id;

    X86_get_op_access()

    return *this;
}

fuku_instruction&  fuku_instruction::set_op_code(const uint8_t* _op_code, uint8_t _lenght) {

    memcpy(this->op_code, _op_code, _lenght);
    this->op_length = _lenght;
    this->op_pref_size = get_prefixes_number();

    return *this;
}

fuku_instruction&  fuku_instruction::set_source_virtual_address(uint64_t va) {

    this->source_virtual_address = va;

    return *this;
}

fuku_instruction&  fuku_instruction::set_virtual_address(uint64_t va) {

    this->virtual_address = va;

    return *this;
}

fuku_instruction&  fuku_instruction::set_label_idx(size_t idx) {

    this->label_idx = idx;

    return *this;
}

fuku_instruction&  fuku_instruction::set_link_label_idx(size_t idx) {

    this->link_label_idx = idx;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_first_idx(size_t idx) {

    this->code_relocation_1_idx = idx;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_second_idx(size_t idx) {

    this->code_relocation_2_idx = idx;

    return *this;
}

fuku_instruction&  fuku_instruction::set_rip_relocation_idx(size_t idx) {

    this->code_rip_relocation_idx = idx;

    return *this;
}

fuku_instruction&  fuku_instruction::set_instruction_flags(uint32_t flags) {

    this->instruction_flags = flags;

    return *this;
}

fuku_instruction&  fuku_instruction::set_eflags(uint64_t eflags) {

    this->eflags = eflags;

    return *this;
}


uint16_t fuku_instruction::get_id() const {
    return this->id;
}

const uint8_t* fuku_instruction::get_op_code() const {
    return this->op_code;
}

uint8_t  fuku_instruction::get_op_length() const {
    return this->op_length;
}

uint8_t  fuku_instruction::get_op_pref_size() const {
    return this->op_pref_size;
}

uint64_t fuku_instruction::get_source_virtual_address() const {
    return this->source_virtual_address;
}

uint64_t fuku_instruction::get_virtual_address() const {
    return this->virtual_address;
}

size_t fuku_instruction::get_label_idx() const {
    return this->label_idx;
}

size_t fuku_instruction::get_link_label_idx() const {
    return this->link_label_idx;
}

size_t fuku_instruction::get_relocation_first_idx() const {
    return this->code_relocation_1_idx;
}

size_t fuku_instruction::get_relocation_second_idx() const {
    return this->code_relocation_2_idx;
}

size_t fuku_instruction::get_rip_relocation_idx() const {
    return this->code_rip_relocation_idx;
}

uint32_t fuku_instruction::get_instruction_flags() const {
    return this->instruction_flags;
}

uint64_t fuku_instruction::get_eflags() const {
    return this->eflags;
}


#include "stdafx.h"
#include "fuku_instruction.h"

fuku_instruction::fuku_instruction(){

    memset(op_code, 0, 16);

    this->op_length     = 0;
    this->op_pref_size  = 0;
    this->source_virtual_address = -1;
    this->virtual_address = 0;                               
    this->ip_relocation_destination = 0;
    this->ip_relocation_disp_offset = 0;
    this->relocation_f_id         = 0;
    this->relocation_f_imm_offset = 0;   
    this->relocation_f_destination = 0;
    this->relocation_s_id         = 0;
    this->relocation_s_imm_offset = 0;
    this->relocation_s_destination = 0;
    this->label_id            = 0;
    this->link_label_id       = 0;
    this->relocation_f_label_id = 0;
    this->relocation_s_label_id = 0;
    this->flags               = 0;
    this->type               = 0;
    this->modified_flags     = 0;
    this->tested_flags       = 0;
    this->useless_flags      = 0;
}

fuku_instruction::fuku_instruction(const fuku_instruction& line) {
    this->operator=(line);
}


fuku_instruction::~fuku_instruction(){

}

fuku_instruction& fuku_instruction::operator=(const fuku_instruction& line) {

    memcpy(this->op_code, line.op_code, line.op_length);
    this->op_length         = line.op_length;
    this->op_pref_size      = line.op_pref_size;
    this->source_virtual_address = line.source_virtual_address;
    this->virtual_address   = line.virtual_address;
    this->ip_relocation_destination = line.ip_relocation_destination;
    this->ip_relocation_disp_offset = line.ip_relocation_disp_offset;
    this->relocation_f_id           = line.relocation_f_id;
    this->relocation_f_imm_offset = line.relocation_f_imm_offset;
    this->relocation_f_destination = line.relocation_f_destination;
    this->relocation_s_id         = line.relocation_s_id;
    this->relocation_s_imm_offset = line.relocation_s_imm_offset;
    this->relocation_s_destination = line.relocation_s_destination;
    this->label_id          = line.label_id;
    this->link_label_id     = line.link_label_id;
    this->relocation_f_label_id = line.relocation_f_label_id;
    this->relocation_s_label_id = line.relocation_s_label_id;
    this->flags             = line.flags;
    this->type              = line.type;
    this->modified_flags    = line.modified_flags;
    this->tested_flags      = line.tested_flags;
    this->useless_flags     = line.useless_flags;

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

bool fuku_instruction::is_jump() const {
    if (this->op_length >= 2) {

        if (
            op_code[op_pref_size] == 0xe9 ||//far jmp
            op_code[op_pref_size] == 0xeb ||//near jmp
            (op_code[op_pref_size] & 0xf0) == 0x70 ||//near jcc
            (op_code[op_pref_size] == 0x0f && (op_code[op_pref_size + 1] & 0xf0) == 0x80) ||//far jcc
            op_code[op_pref_size] == 0xe8 ||//call
            (op_code[op_pref_size] >= 0xe0 && op_code[op_pref_size] <= 0xe3)//loopx jecxz
            ) {

            return true;
        }
    }
    return false;
}

int32_t fuku_instruction::get_jump_imm() const {

    if (
        (op_code[op_pref_size] >= 0xe0 && op_code[op_pref_size] <= 0xe3) ||
        op_code[op_pref_size] == 0xeb ||
        (op_code[op_pref_size] & 0xf0) == 0x70
        ) {
        return (int32_t)*(char*)&op_code[op_pref_size + 1];
    }
    else if (
        op_code[op_pref_size] == 0xe8 ||
        op_code[op_pref_size] == 0xe9
        ) {
        return *(int32_t*)&op_code[op_pref_size + 1];
    }
    else if (
        (op_code[op_pref_size] == 0x0f && (op_code[op_pref_size + 1] & 0xf0) == 0x80)
        ) { //far jcc
        return *(int32_t*)&op_code[op_pref_size + 2];
    }

    return 0;
}

void fuku_instruction::set_jump_imm(uint64_t destination_virtual_address) {

    switch (op_code[op_pref_size]) {

        case 0xE9:case 0xE8: { //far jmp //call far\near
            *(uint32_t*)&op_code[op_pref_size + 1] = uint32_t(destination_virtual_address - virtual_address - op_length);
            break;
        }

        case 0x0F: { //jcc far
            switch (op_code[op_pref_size + 1])
            {
            case 0x80:case 0x81:case 0x82:case 0x83:case 0x84:case 0x85:case 0x86:case 0x87: //jcc far
            case 0x88:case 0x89:case 0x8A:case 0x8B:case 0x8C:case 0x8D:case 0x8E:case 0x8F: {
                *(uint32_t*)&op_code[op_pref_size + 2] = uint32_t(destination_virtual_address - virtual_address - op_length );
                break;
            }

            default: { break; }
            }
            break;
        }
    }
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

fuku_instruction&  fuku_instruction::set_ip_relocation_destination(uint64_t dst_va) {
    this->ip_relocation_destination = dst_va;

    return *this;
}

fuku_instruction&  fuku_instruction::set_ip_relocation_disp_offset(uint8_t offset) {

    if (offset > 8) {
        __debugbreak();
    }

    this->ip_relocation_disp_offset = offset;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_f_id(uint32_t id) {
    this->relocation_f_id = id;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_f_imm_offset(uint8_t offset) {
    this->relocation_f_imm_offset = offset;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_f_destination(uint64_t dst) {
    this->relocation_f_destination = dst;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_s_id(uint32_t id) {
    this->relocation_s_id = id;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_s_imm_offset(uint8_t offset) {
    this->relocation_s_imm_offset = offset;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_s_destination(uint64_t dst) {
    this->relocation_s_destination = dst;

    return *this;
}

fuku_instruction&  fuku_instruction::set_label_id(uint32_t id) {
    this->label_id = id;

    return *this;
}
fuku_instruction&  fuku_instruction::set_link_label_id(uint32_t id) {
    this->link_label_id = id;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_f_label_id(uint32_t id) {
    this->relocation_f_label_id = id;

    return *this;
}

fuku_instruction&  fuku_instruction::set_relocation_s_label_id(uint32_t id) {
    this->relocation_s_label_id = id;

    return *this;
}

fuku_instruction&  fuku_instruction::set_flags(uint32_t flags) {
    this->flags = flags;

    return *this;
}

fuku_instruction&  fuku_instruction::set_type(uint16_t type) {
    this->type = type;

    return *this;
}

fuku_instruction&  fuku_instruction::set_modified_flags(uint16_t modified_flags) {
    this->modified_flags = modified_flags;

    return *this;
}

fuku_instruction&  fuku_instruction::set_tested_flags(uint16_t tested_flags) {
    this->tested_flags = tested_flags;

    return *this;
}

fuku_instruction&  fuku_instruction::set_useless_flags(uint16_t useless_flags) {
    this->useless_flags = useless_flags;

    return *this;
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

uint64_t fuku_instruction::get_ip_relocation_destination() const {
    return this->ip_relocation_destination;
}

uint8_t	 fuku_instruction::get_ip_relocation_disp_offset() const {
    return this->ip_relocation_disp_offset;
}

uint32_t fuku_instruction::get_relocation_f_id() const {
    return this->relocation_f_id;
}
uint8_t	 fuku_instruction::get_relocation_f_imm_offset() const {
    return this->relocation_f_imm_offset;
}
uint64_t fuku_instruction::get_relocation_f_destination() const {
    return this->relocation_f_destination;
}
uint32_t fuku_instruction::get_relocation_s_id() const {
    return this->relocation_s_id;
}
uint8_t	 fuku_instruction::get_relocation_s_imm_offset() const {
    return this->relocation_s_imm_offset;
}
uint64_t fuku_instruction::get_relocation_s_destination() const {
    return this->relocation_s_destination;
}
uint32_t fuku_instruction::get_label_id() const {
    return this->label_id;
}
uint32_t fuku_instruction::get_link_label_id() const {
    return this->link_label_id;
}

uint32_t fuku_instruction::get_relocation_f_label_id() const {
    return this->relocation_f_label_id;
}

uint32_t fuku_instruction::get_relocation_s_label_id() const {
    return this->relocation_s_label_id;
}


uint32_t fuku_instruction::get_flags() const {
    return this->flags;
}

uint16_t fuku_instruction::get_type() const {
    return this->type;
}

uint16_t fuku_instruction::get_modified_flags() const {
    return this->modified_flags;
}

uint16_t fuku_instruction::get_tested_flags() const {
    return this->tested_flags;
}

uint16_t fuku_instruction::get_useless_flags() const {
    return this->useless_flags;
}

fuku_instruction * get_line_by_va(const linestorage& lines, uint64_t virtual_address) {

    size_t left = 0;
    size_t right = lines.size();
    size_t mid = 0;

    while (left < right) {
        mid = left + (right - left) / 2;

        if (lines[mid].get_virtual_address() <= virtual_address &&
            lines[mid].get_source_virtual_address() + lines[mid].get_op_length() > virtual_address) {

            return (fuku_instruction *)&lines[mid];
        }
        else if (lines[mid].get_virtual_address() > virtual_address) {
            right = mid;
        }
        else {
            left = mid + 1;
        }
    }

    return 0;
}

fuku_instruction * get_line_by_label_id(const linestorage& lines, const std::vector<uint32_t>& labels_cache, unsigned int label_id) {

    if (labels_cache.size()) {
        if (label_id > 0 && label_id <= labels_cache.size()) {
            return (fuku_instruction *)&lines[labels_cache[label_id - 1]];
        }
    }

    return 0;
}

#include "stdafx.h"
#include "obfurikuristruction.h"


obfurikuristruction::obfurikuristruction(){

    memset(op_code, 0, sizeof(op_code));

    this->op_length     = 0;
    this->op_pref_size  = 0;
    this->source_virtual_address = 0;
    this->virtual_address = 0;                               
    this->ip_relocation_destination = 0;
    this->ip_relocation_disp_offset = 0;
    this->relocation_id         = 0;
    this->relocation_imm_offset = 0;                       
    this->label_id            = 0;
    this->link_label_id       = 0;
    this->relocation_label_id = 0;
    this->flags               = 0;
}


obfurikuristruction::~obfurikuristruction(){

}


uint8_t obfurikuristruction::get_prefixes_number() {
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

bool obfurikuristruction::is_jump() const {
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

int32_t obfurikuristruction::get_jump_imm() const {

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
        return *(int*)&op_code[op_pref_size + 1];
    }
    else if (
        (op_code[op_pref_size] == 0x0f && (op_code[op_pref_size + 1] & 0xf0) == 0x80)
        ) { //far jcc
        return *(int32_t*)&op_code[op_pref_size + 2];
    }

    return 0;
}

void obfurikuristruction::set_jump_imm(uint64_t destination_virtual_address) {

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
                *(uint32_t*)&op_code[op_pref_size + 2] = uint32_t(destination_virtual_address - virtual_address - op_length);
                break;
            }

            default: { break; }
            }
            break;
        }
    }
}

void  obfurikuristruction::set_op_code(uint8_t* _op_code, uint8_t _lenght) {

    memcpy(this->op_code, _op_code, _lenght);
    this->op_length = _lenght;
    this->op_pref_size = get_prefixes_number();
}

void  obfurikuristruction::set_source_virtual_address(uint64_t va) {
    this->source_virtual_address = va;
}
void  obfurikuristruction::set_virtual_address(uint64_t va) {
    this->virtual_address = va;
}

void  obfurikuristruction::set_ip_relocation_destination(uint64_t dst_va) {
    this->ip_relocation_destination = dst_va;
}

void  obfurikuristruction::set_ip_relocation_disp_offset(uint8_t offset) {
    this->ip_relocation_disp_offset = offset;
}

void  obfurikuristruction::set_relocation_id(uint32_t id) {
    this->relocation_id = id;
}
void  obfurikuristruction::set_relocation_imm_offset(uint8_t offset) {
    this->relocation_imm_offset = offset;
}

void  obfurikuristruction::set_label_id(uint32_t id) {
    this->label_id = id;
}
void  obfurikuristruction::set_link_label_id(uint32_t id) {
    this->link_label_id = id;
}
void  obfurikuristruction::set_relocation_label_id(uint32_t id) {
    this->relocation_label_id = id;
}

void  obfurikuristruction::set_flags(uint32_t flags) {
    this->flags = flags;
}


const uint8_t* obfurikuristruction::get_op_code() const {
    return this->op_code;
}

uint8_t  obfurikuristruction::get_op_length() const {
    return this->op_length;
}

uint8_t  obfurikuristruction::get_op_pref_size() const {
    return this->op_pref_size;
}

uint64_t obfurikuristruction::get_source_virtual_address() const {
    return this->source_virtual_address;
}

uint64_t obfurikuristruction::get_virtual_address() const {
    return this->virtual_address;
}

uint64_t obfurikuristruction::get_ip_relocation_destination() const {
    return this->ip_relocation_destination;
}

uint8_t	 obfurikuristruction::get_ip_relocation_disp_offset() const {
    return this->ip_relocation_disp_offset;
}

uint32_t obfurikuristruction::get_relocation_id() const {
    return this->relocation_id;
}
uint8_t	 obfurikuristruction::get_relocation_imm_offset() const {
    return this->relocation_imm_offset;
}

uint32_t obfurikuristruction::get_label_id() const {
    return this->label_id;
}
uint32_t obfurikuristruction::get_link_label_id() const {
    return this->link_label_id;
}
uint32_t obfurikuristruction::get_relocation_label_id() const {
    return this->relocation_label_id;
}

uint32_t obfurikuristruction::get_flags() const {
    return this->flags;
}
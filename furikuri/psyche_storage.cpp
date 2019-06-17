#include "stdafx.h"
#include "psyche_storage.h"


psyche_storage::psyche_storage() 
    :target_module(0), code_holder(0) {}

psyche_storage::psyche_storage(shibari_module* target_module, fuku_code_holder* code_holder) 
    :target_module(target_module), code_holder(code_holder) {}

psyche_storage::~psyche_storage() {

}


void psyche_storage::set_target_module(shibari_module* module_) {
    this->target_module = module_;
}

void psyche_storage::set_code_holder(fuku_code_holder* holder) {
    this->code_holder = holder;
}

void psyche_storage::set_psy_blocks(const blocks_table& blocks) {
    this->blocks = blocks;
}

const shibari_module* psyche_storage::get_target_module() const {
    return this->target_module;
}

shibari_module* psyche_storage::get_target_module() {
    return this->target_module;
}

const psyche_pcode_manager& psyche_storage::get_pcode_manager() const {
    return this->pcode_manager;
}

psyche_pcode_manager& psyche_storage::get_pcode_manager() {
    return this->pcode_manager;
}

const fuku_code_holder* psyche_storage::get_code_holder() const {
    return this->code_holder;
}

fuku_code_holder* psyche_storage::get_code_holder() {
    return this->code_holder;
}

const blocks_table& psyche_storage::get_blocks_table() const {
    return this->blocks;
}

blocks_table& psyche_storage::get_blocks_table() {
    return this->blocks;
}

const psyche_handler_manager& psyche_storage::get_handler_manager() const{
    return this->handler_manager;
}

psyche_handler_manager& psyche_storage::get_handler_manager() {
    return this->handler_manager;
}

const fuku_code_holder& psyche_storage::get_vm() const {
    return this->vm;
}

fuku_code_holder& psyche_storage::get_vm() {
    return this->vm;
}
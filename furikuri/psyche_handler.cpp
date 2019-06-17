#include "stdafx.h"
#include "psyche_handler.h"


psyche_handler_sign::psyche_handler_sign() {

}

psyche_handler_sign::psyche_handler_sign(const psyche_handler_sign& sign) {
    operator=(sign);
}

psyche_handler_sign::psyche_handler_sign(const psyche_block& parent_block, const psyche_cmd& cmd) {
    this->operator=(std::pair<const psyche_block&, const psyche_cmd&>(parent_block, cmd));
}

psyche_handler_sign::~psyche_handler_sign() {}

psyche_handler_sign& psyche_handler_sign::operator=(const psyche_handler_sign& sign) {

    this->sign = sign.sign;

    return *this;
}

psyche_handler_sign& psyche_handler_sign::operator=(std::pair<const psyche_block&, const psyche_cmd&> cmd) {

    size_t props_size = cmd.first.get_properties().size() * sizeof(uint16_t); 

    for (auto& prop : cmd.first.get_properties()) {
        props_size += sizeof(uint32_t) + (prop.second.size() * sizeof(uint32_t) + sizeof(uint16_t));
    }

    this->sign.resize(
        sizeof(fuku_assambler_arch) + //arch
        sizeof(uint32_t) + sizeof(uint8_t) + //opcode + size
        props_size //props
    );
    
    size_t vec_pos = 0;
    
    *(uint8_t*)&this->sign.data()[vec_pos] = cmd.first.get_arch(); vec_pos += sizeof(uint8_t);
    *(uint32_t*)&this->sign.data()[vec_pos] = cmd.second.get_opcode(); vec_pos += sizeof(uint32_t);
    *(uint8_t*)& this->sign.data()[vec_pos] = cmd.second.get_size(); vec_pos += sizeof(uint8_t);

    *(uint16_t*)&this->sign.data()[vec_pos] = (uint16_t)cmd.first.get_properties().size(); vec_pos += sizeof(uint16_t);

    for (auto prop : cmd.first.get_properties()) {
        *(uint32_t*)&this->sign.data()[vec_pos] = prop.first;  vec_pos += sizeof(uint32_t);
        *(uint16_t*)&this->sign.data()[vec_pos] = (uint16_t)prop.second.size();  vec_pos += sizeof(uint16_t);

        for (auto prop_val : prop.second) {
            *(uint32_t*)&this->sign.data()[vec_pos] = prop_val;  vec_pos += sizeof(uint32_t);
        }
    }


    return *this;
}

bool psyche_handler_sign::operator==(const psyche_handler_sign& sign) const {

    if (this->sign.size() == sign.sign.size() &&
        !memcmp(this->sign.data(), sign.sign.data(), this->sign.size())) {

        return true;
    }

    return false;
}

bool psyche_handler_sign::operator<(const psyche_handler_sign& rsign) const {
 
    return std::tie(sign, static_cast<std::vector<uint8_t> const&>(this->sign)) <
        std::tie(rsign.sign, static_cast<std::vector<uint8_t> const&>(rsign.sign));
}

void psyche_handler_sign::set_sign(std::vector<uint8_t>& sign) {
    this->sign = sign;
}

void psyche_handler_sign::get_extended_sign(psyche_handler_sign_extended& sign) const {
   
    sign.op.opcode = 0;
    sign.op.size = 0;
    sign.properies.clear();

    auto& raw_blob = this->sign;

    size_t vec_pos = 0;

    if (raw_blob.size() >= sizeof(uint8_t)) {
        
        sign.arch = *(uint8_t*)(&raw_blob.data()[vec_pos]); vec_pos += sizeof(uint8_t);

        if (raw_blob.size() >= sizeof(psyche_handler_sign_op_header) + sizeof(uint8_t)) {

            psyche_handler_sign_op_header* op = (psyche_handler_sign_op_header*)(&raw_blob.data()[vec_pos]);
            sign.op.opcode = op->opcode;
            sign.op.size = op->size;

            vec_pos += sizeof(psyche_handler_sign_op_header);


            if (raw_blob.size() > vec_pos) {

                uint16_t props_count = *(uint16_t*)&raw_blob.data()[vec_pos]; vec_pos += sizeof(uint16_t);

                for (uint8_t prop_idx = 0; prop_idx < props_count && raw_blob.size() > vec_pos; prop_idx++) {

                    uint32_t key = *(uint32_t*)&raw_blob.data()[vec_pos]; vec_pos += sizeof(uint32_t);
                    uint16_t val_count = *(uint16_t*)&raw_blob.data()[vec_pos]; vec_pos += sizeof(uint16_t);

                    std::vector<uint32_t> values;

                    for (uint8_t val_idx = 0; val_idx < val_count && raw_blob.size() > vec_pos; val_idx++) {
                        values.push_back(*(uint32_t*)&raw_blob.data()[vec_pos]); vec_pos += sizeof(uint32_t);
                    }

                    sign.properies[key] = values;
                }
            }
        }
    }
}

std::vector<uint8_t>& psyche_handler_sign::get_sign() {
    return this->sign;
}

const std::vector<uint8_t>& psyche_handler_sign::get_sign() const {
    return this->sign;
}

std::vector< psyche_cmd*>& psyche_handler_sign::get_refs() {
    return this->refs;
}

const std::vector< psyche_cmd*>& psyche_handler_sign::get_refs() const {
    return this->refs;
}

psyche_handler::psyche_handler() 
    : handler_label(-1) {}

psyche_handler::psyche_handler(const psyche_handler& handler) {
    this->operator=(handler);
}

psyche_handler::~psyche_handler() {

}

psyche_handler& psyche_handler::operator=(const psyche_handler& handler) {

    this->handler_label = handler.handler_label;
    this->handler_properies = handler.handler_properies;

    return *this;
}

void psyche_handler::set_handler_label(size_t label) {
    this->handler_label = label;
}

size_t psyche_handler::get_handler_label() const {
    return this->handler_label;
}


std::map<uint32_t, uint64_t>& psyche_handler::get_handler_properies() {
    return this->handler_properies;
}

const std::map<uint32_t, uint64_t>& psyche_handler::get_handler_properies() const {
    return this->handler_properies;
}



psyche_handler_manager::psyche_handler_manager() {

}

psyche_handler_manager::~psyche_handler_manager() {

}

void psyche_handler_manager::add_handler(const psyche_handler& handler, const psyche_handler_sign& signature) {

    handlers.push_back(handler);

    auto handle_ptr = &handlers.back();

    handlers_link[signature].push_back(handle_ptr);
    handlers_sign_link[handle_ptr] = signature;
}

void psyche_handler_manager::link_cmd_handler(psyche_cmd* cmd, psyche_handler* handler) {

    handlers_link_table[cmd] = handler;
    cmd->set_handler_entry(handler);
}

std::vector<psyche_handler*>* psyche_handler_manager::get_handler_vec(const psyche_handler_sign& signature) {

    auto link_sign = handlers_link.find(signature);

    if (link_sign != this->handlers_link.end()) {
        return &link_sign->second;
    }
    else {
        return 0;
    }
}

const std::vector<psyche_handler*>* psyche_handler_manager::get_handler_vec(const psyche_handler_sign& signature) const {

    auto link_sign = handlers_link.find(signature);

    if (link_sign != this->handlers_link.end()) {
        return &link_sign->second;
    }
    else {
        return 0;
    }
}

psyche_handler_sign* psyche_handler_manager::get_handler_sign(const psyche_handler* handler) {

    auto link_sign = handlers_sign_link.find((psyche_handler*)handler);

    if (link_sign != this->handlers_sign_link.end()) {
        return &link_sign->second;
    }
    else {
        return 0;
    }
}

const psyche_handler_sign* psyche_handler_manager::get_handler_sign(const psyche_handler* handler) const {

    auto link_sign = handlers_sign_link.find((psyche_handler*)handler);

    if (link_sign != this->handlers_sign_link.end()) {
        return &link_sign->second;
    }
    else {
        return 0;
    }
}

psyche_handler* psyche_handler_manager::get_handler(psyche_cmd* cmd) {
    auto link_handler = this->handlers_link_table.find(cmd);

    if (link_handler != this->handlers_link_table.end()) {
        return link_handler->second;
    }
    else {
        return 0;
    }
}

const psyche_handler* psyche_handler_manager::get_handler(psyche_cmd* cmd) const {
    auto link_handler = this->handlers_link_table.find(cmd);

    if (link_handler != this->handlers_link_table.end()) {
        return link_handler->second;
    }
    else {
        return 0;
    }
}

std::list<psyche_handler>& psyche_handler_manager::get_handlers() {
    return this->handlers;
}

const std::list<psyche_handler>& psyche_handler_manager::get_handlers() const {
    return this->handlers;
}

std::map<psyche_handler*, psyche_handler_sign>& psyche_handler_manager::get_handlers_sign_link() {
    return this->handlers_sign_link;
}

const std::map<psyche_handler*, psyche_handler_sign>& psyche_handler_manager::get_handlers_sign_link() const {
    return this->handlers_sign_link;
}

std::map<psyche_cmd*, psyche_handler*>& psyche_handler_manager::get_handlers_link_table() {
    return this->handlers_link_table;
}
const std::map<psyche_cmd*, psyche_handler*>& psyche_handler_manager::get_handlers_link_table() const {
    return this->handlers_link_table;
}
#include "stdafx.h"
#include "psyche_cmd.h"


psyche_cmd_arg::psyche_cmd_arg()
    :size(0), type(0), value(0) {}

psyche_cmd_arg::psyche_cmd_arg(const psyche_cmd_arg& arg) {
    this->operator=(arg);
}

psyche_cmd_arg::psyche_cmd_arg(uint8_t size, uint32_t type, uint64_t value)
    :size(size), type(type), value(value) {}

psyche_cmd_arg::~psyche_cmd_arg() {

}


psyche_cmd_arg& psyche_cmd_arg::operator=(const psyche_cmd_arg& arg) {

    this->size = arg.size;
    this->type = arg.type;
    this->value = arg.value;

    return *this;
}

void psyche_cmd_arg::set_size(uint8_t size) {
    this->size = size;
}

void psyche_cmd_arg::set_type(uint32_t type) {
    this->type = type;
}

void psyche_cmd_arg::set_value(uint64_t val) {
    this->value = val;
}


uint8_t psyche_cmd_arg::get_size() const {
    return this->size;
}

uint32_t psyche_cmd_arg::get_type() const {
    return this->type;
}

uint64_t psyche_cmd_arg::get_value() const {
    return this->value;
}


psyche_cmd::psyche_cmd() 
    :size(0), opcode(0), parent(0), handler_entry(0), pcode_entry(0) { }

psyche_cmd::psyche_cmd(const psyche_cmd& command) {
    this->operator=(command);
}

psyche_cmd::psyche_cmd(uint8_t size, uint32_t opcode)
    :size(size), opcode(opcode), parent(0), handler_entry(0), pcode_entry(0) { }

psyche_cmd::psyche_cmd(uint8_t size, uint32_t opcode, const psyche_cmd_arg& arg_1)
    : size(size), opcode(opcode), parent(0), handler_entry(0), pcode_entry(0) {

    args.push_back(arg_1);
}

psyche_cmd::psyche_cmd(uint8_t size, uint32_t opcode, const psyche_cmd_arg& arg_1, const psyche_cmd_arg& arg_2)
    : size(size), opcode(opcode), parent(0), handler_entry(0), pcode_entry(0) {

    args.push_back(arg_1);
    args.push_back(arg_2);
}

psyche_cmd::psyche_cmd(uint8_t size, uint32_t opcode, const psyche_cmd_arg& arg_1, const psyche_cmd_arg& arg_2, const psyche_cmd_arg& arg_3)
    : size(size), opcode(opcode), parent(0), handler_entry(0), pcode_entry(0) {

    args.push_back(arg_1);
    args.push_back(arg_2);
    args.push_back(arg_3);
}

psyche_cmd::~psyche_cmd(){}

psyche_cmd& psyche_cmd::operator=(const psyche_cmd& command) {

    this->size = command.size;
    this->opcode = command.opcode;
    this->args = command.args;
    this->parent = command.parent;
    this->handler_entry = command.handler_entry;
    this->pcode_entry = command.pcode_entry;
    return *this;
}

void psyche_cmd::set_size(uint8_t size) {
    this->size = size;
}

void psyche_cmd::set_opcode(uint32_t op) {
    this->opcode = op;
}

void psyche_cmd::set_args(const std::vector<psyche_cmd_arg>& args) {
    this->args = args;
}

void psyche_cmd::set_parent(psyche_block * parent) {
    this->parent = parent;
}

void psyche_cmd::set_handler_entry(psyche_handler* handler_entry) {
    this->handler_entry = handler_entry;
}

void psyche_cmd::set_pcode_entry(psyche_pcode* pcode_entry) {
    this->pcode_entry = pcode_entry;
}

uint8_t psyche_cmd::get_size() const {
    return this->size;
}

uint32_t psyche_cmd::get_opcode() const {
    return this->opcode;
}

const psyche_block* psyche_cmd::get_parent() const {
    return this->parent;
}

psyche_block* psyche_cmd::get_parent() {
    return this->parent;
}

const psyche_handler* psyche_cmd::get_handler_entry() const {
    return this->handler_entry;
}

psyche_handler* psyche_cmd::get_handler_entry() {
    return this->handler_entry;
}

const psyche_pcode* psyche_cmd::get_pcode_entry() const {
    return this->pcode_entry;
}

psyche_pcode* psyche_cmd::get_pcode_entry() {
    return this->pcode_entry;
}

const std::vector<psyche_cmd_arg>& psyche_cmd::get_args() const {
    return this->args;
}

std::vector<psyche_cmd_arg>& psyche_cmd::get_args() {
    return this->args;
}

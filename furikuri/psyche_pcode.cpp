#include "stdafx.h"
#include "psyche_pcode.h"

psyche_pcode_manager::psyche_pcode_manager() {}
psyche_pcode_manager::~psyche_pcode_manager() {}





void psyche_pcode_manager::add_pcode(const psyche_block* block, psyche_cmd* cmd, const psyche_pcode& pcode_entry) {

}

psyche_pcode * psyche_pcode_manager::get_cmd_pcode(const  psyche_cmd* cmd) {

    auto link_cmd = this->cmd_link_table.find((psyche_cmd*)cmd);

    if (link_cmd != this->cmd_link_table.end()) {
        return link_cmd->second;
    }
    else {
        return 0;
    } 
}

const psyche_pcode * psyche_pcode_manager::get_cmd_pcode(const  psyche_cmd* cmd) const {

    auto link_cmd = this->cmd_link_table.find((psyche_cmd*)cmd);

    if (link_cmd != this->cmd_link_table.end()) {
        return link_cmd->second;
    }
    else {
        return 0;
    }
}

psyche_block_pcode_table * psyche_pcode_manager::get_block_pcode(const psyche_block* block) {

    auto link_block = this->block_link_table.find((psyche_block*)block);

    if (link_block != this->block_link_table.end()) {
        return link_block->second;
    }
    else {
        return 0;
    }
}

const psyche_block_pcode_table * psyche_pcode_manager::get_block_pcode(const  psyche_block* block) const {

    auto link_block = this->block_link_table.find((psyche_block*)block);

    if (link_block != this->block_link_table.end()) {
        return link_block->second;
    }
    else {
        return 0;
    }
}

std::list<psyche_block_pcode_table>&  psyche_pcode_manager::get_block_pcode_table() {
    return this->block_pcode_table;
}

const std::list<psyche_block_pcode_table>&  psyche_pcode_manager::get_block_pcode_table() const {
    return this->block_pcode_table;
}

std::list<psyche_pcode>& psyche_pcode_manager::get_cmd_pcode_table() {
    return this->cmd_pcode_table;
}

const std::list<psyche_pcode>& psyche_pcode_manager::get_cmd_pcode_table() const {
    return this->cmd_pcode_table;
}

std::map<psyche_block*, psyche_block_pcode_table*>& psyche_pcode_manager::get_block_link_table() {
    return this->block_link_table;
}

const std::map<psyche_block*, psyche_block_pcode_table*>& psyche_pcode_manager::get_block_link_table() const {
    return this->block_link_table;
}

std::map<psyche_cmd*, psyche_pcode*>& psyche_pcode_manager::get_cmd_link_table() {
    return this->cmd_link_table;
}

const std::map<psyche_cmd*, psyche_pcode*>& psyche_pcode_manager::get_cmd_link_table() const {
    return this->cmd_link_table;
}
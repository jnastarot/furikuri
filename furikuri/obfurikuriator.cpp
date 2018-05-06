#include "stdafx.h"
#include "obfurikuriator.h"


obfurikuriator::obfurikuriator(){
    this->arch = obfkt_arch::obfkt_arch_x32;

    this->destination_virtual_address = 0;

    this->complexity = 1;
    this->number_of_passes = 1;

    this->association_table = 0; 
    this->relocations       = 0;
    this->ip_relocations    = 0;
}


obfurikuriator::~obfurikuriator(){
}

void obfurikuriator::set_arch(obfkt_arch arch) {
    this->arch = arch;
}

void obfurikuriator::set_destination_virtual_address(uint64_t destination_virtual_address) {
    this->destination_virtual_address = destination_virtual_address;
}

void obfurikuriator::set_complexity(unsigned int complexity) {
    this->complexity = complexity;
}

void obfurikuriator::set_number_of_passes(unsigned int number_of_passes) {
    this->number_of_passes = number_of_passes;
}

void obfurikuriator::set_association_table(std::vector<obfkt_association>*	associations) {
    this->association_table = associations;
}

void obfurikuriator::set_relocation_table(std::vector<obfkt_relocation>* relocations) {
    this->relocations = relocations;
}

void obfurikuriator::set_ip_relocation_table(std::vector<obfkt_ip_relocations>* ip_relocations) {
    this->ip_relocations = ip_relocations;
}

obfkt_arch   obfurikuriator::get_arch() {
    return this->arch;
}

uint64_t     obfurikuriator::get_destination_virtual_address() {
    return this->destination_virtual_address;
}

unsigned int obfurikuriator::get_complexity() {
    return this->complexity;
}

unsigned int obfurikuriator::get_number_of_passes() {
    return this->number_of_passes;
}

std::vector<obfkt_association>*    obfurikuriator::get_association_table() {
    return this->association_table;
}

std::vector<obfkt_relocation>*     obfurikuriator::get_relocation_table() {
    return this->relocations;
}

std::vector<obfkt_ip_relocations>* obfurikuriator::get_ip_relocation_table() {
    return this->ip_relocations;
}

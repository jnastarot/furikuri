#pragma once

#include "obfurikuristruction.h"

enum obfkt_arch {
    obfkt_arch_x32,
    obfkt_arch_x64
};

struct obfkt_association {
    uint64_t prev_virtual_address;
    uint64_t virtual_address;
};
struct obfkt_relocation {
    uint64_t virtual_address;
    uint32_t relocation_id;
};
struct obfkt_ip_relocations {
    uint64_t    virtual_address;				
    uint64_t    destination_virtual_address;
    uint8_t     disp_relocation_offset;
    uint8_t     instruction_size;
};


class obfurikuriator {
    obfkt_arch arch;

    uint64_t destination_virtual_address;

    unsigned int complexity;
    unsigned int number_of_passes;

    std::vector<obfkt_association>*     association_table;
    std::vector<obfkt_relocation>*      relocations;
    std::vector<obfkt_ip_relocations>*  ip_relocations;
public:
    obfurikuriator::obfurikuriator();
    obfurikuriator::~obfurikuriator();


public:
    void obfurikuriator::set_arch(obfkt_arch arch);
    void obfurikuriator::set_destination_virtual_address(uint64_t destination_virtual_address);
    void obfurikuriator::set_complexity(unsigned int complexity);
    void obfurikuriator::set_number_of_passes(unsigned int number_of_passes);

    void obfurikuriator::set_association_table(std::vector<obfkt_association>*	associations);
    void obfurikuriator::set_relocation_table(std::vector<obfkt_relocation>* relocations);
    void obfurikuriator::set_ip_relocation_table(std::vector<obfkt_ip_relocations>* ip_relocations);
public:  
    obfkt_arch   obfurikuriator::get_arch();
    uint64_t     obfurikuriator::get_destination_virtual_address();
    unsigned int obfurikuriator::get_complexity();
    unsigned int obfurikuriator::get_number_of_passes();

    std::vector<obfkt_association>*    obfurikuriator::get_association_table();
    std::vector<obfkt_relocation>*     obfurikuriator::get_relocation_table();
    std::vector<obfkt_ip_relocations>* obfurikuriator::get_ip_relocation_table();
};

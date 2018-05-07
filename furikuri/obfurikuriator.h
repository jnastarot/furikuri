#pragma once
#include "..\distorm_lib\include\distorm.h"
#include "..\distorm_lib\include\mnemonics.h"

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

#include "obfurikuristruction.h"



class obfurikuriator {
    obfkt_arch arch;

    uint64_t destination_virtual_address;

    unsigned int complexity;
    unsigned int number_of_passes;

    unsigned int label_seed;
    std::vector<obfurikuristruction*> labels_cache;
    std::vector<obfurikuristruction>  lines;

    std::vector<obfkt_association>*     association_table;
    std::vector<obfkt_relocation>*      relocations;
    std::vector<obfkt_ip_relocations>*  ip_relocations;

    bool obfurikuriator::analyze_code(
        uint8_t * src, uint32_t src_len,
        uint64_t virtual_address,
        std::vector<obfurikuristruction>&  lines,
        std::vector<obfkt_relocation>*	relocations);

    std::vector<uint8_t> obfurikuriator::obfuscate(std::vector<obfurikuristruction>& lines, unsigned int recurse_idx);

    void obfurikuriator::spagetti_code(std::vector<obfurikuristruction>& lines, uint64_t virtual_address);

    void obfurikuriator::handle_jmps(std::vector<obfurikuristruction>& lines);
    void obfurikuriator::finalize_jmps(std::vector<obfurikuristruction>& lines);

    void    obfurikuriator::lines_correction(std::vector<obfurikuristruction>& lines, uint64_t virtual_address);
    obfurikuristruction * obfurikuriator::get_line_by_va(std::vector<obfurikuristruction>& lines, uint64_t virtual_address);
    obfurikuristruction * obfurikuriator::get_line_by_source_va(std::vector<obfurikuristruction>& lines, uint64_t virtual_address);
    obfurikuristruction * obfurikuriator::get_line_by_label_id(unsigned int label_id);
    std::vector<uint8_t>  obfurikuriator::lines_to_bin(std::vector<obfurikuristruction>&  lines);
public:
    obfurikuriator::obfurikuriator();
    obfurikuriator::~obfurikuriator();

    std::vector<uint8_t> obfurikuriator::obfuscate();

    bool obfurikuriator::push_code(
        uint8_t * src, uint32_t src_len,
        uint64_t virtual_address,
        std::vector<obfkt_relocation>*	relocations);
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

public://internal use
    uint32_t obfurikuriator::set_label(obfurikuristruction& line);
    uint32_t obfurikuriator::get_maxlabel();
};

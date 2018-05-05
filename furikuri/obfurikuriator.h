#pragma once

enum obfkt_arch {
    enma_arch_x32,
    enma_arch_x64
};

struct obfkt_association {
    uint64_t prev_virtual_address;
    uint64_t virtual_address;
};
struct obfkt_relocation {
    uint64_t virtual_address;
    uint32_t relocation_id;
};
struct obfkt_label {
    uint64_t virtual_address;
    uint32_t label_id;
};
struct obfkt_callout {
    uint32_t    instruction_offset;				//offset to jmp in obfuscated code
    uint64_t    destination_virtual_address;    //related to this rva
    uint8_t     imm_rel_offset;
    uint8_t     instruction_size;
};


class obfurikuriator {
    obfkt_arch arch;

    uint64_t virtual_address;
    uint64_t destination_virtual_address;

    unsigned int complexity;
    unsigned int number_of_passes;

    std::vector<obfkt_association>* association;
    std::vector<obfkt_relocation>*  relocations;
    std::vector<obfkt_label>*       code_labels;
    std::vector<obfkt_callout>*     callouts;
public:
    obfurikuriator::obfurikuriator();
    obfurikuriator::~obfurikuriator();

    void obfurikuriator::set_arch(obfkt_arch arch);
    void obfurikuriator::set_virtual_address(uint64_t virtual_address);
    void obfurikuriator::set_destination_virtual_address(uint64_t destination_virtual_address);
    void obfurikuriator::set_complexity(unsigned int complexity);
    void obfurikuriator::set_number_of_passes(unsigned int number_of_passes);

    void obfurikuriator::set_association_table(std::vector<obfkt_association>*	association);
    void obfurikuriator::set_relocation_table(std::vector<obfkt_relocation>* relocations);
    void obfurikuriator::set_label_table(std::vector<obfkt_label>*	code_labels);
    void obfurikuriator::set_callout_table(std::vector<obfkt_callout>* callouts);
};

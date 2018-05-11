#pragma once


enum ob_fuku_arch {
    ob_fuku_arch_x32,
    ob_fuku_arch_x64
};

struct ob_fuku_association {
    uint64_t prev_virtual_address;
    uint64_t virtual_address;
};
struct ob_fuku_relocation {
    uint64_t virtual_address;
    uint32_t relocation_id;
};
struct ob_fuku_ip_relocations {
    uint64_t    virtual_address;				
    uint64_t    destination_virtual_address;
    uint8_t     disp_relocation_offset;
    uint8_t     instruction_size;
};


class fuku_obfuscator {
    ob_fuku_arch arch;

    uint64_t destination_virtual_address;

    unsigned int complexity;
    unsigned int number_of_passes;

    unsigned int label_seed;
    std::vector<fuku_instruction*> labels_cache;
    std::vector<fuku_instruction>  lines;

    std::vector<ob_fuku_association>*     association_table;
    std::vector<ob_fuku_relocation>*      relocations;
    std::vector<ob_fuku_ip_relocations>*  ip_relocations;

    bool fuku_obfuscator::analyze_code(
        uint8_t * src, uint32_t src_len,
        uint64_t virtual_address,
        std::vector<fuku_instruction>&  lines,
        std::vector<ob_fuku_relocation>*	relocations);

    void fuku_obfuscator::spagetti_code(std::vector<fuku_instruction>& lines, uint64_t virtual_address);

    void fuku_obfuscator::build_tables(
        std::vector<fuku_instruction>& lines,
        std::vector<ob_fuku_association>* association,
        std::vector<ob_fuku_relocation>*	relocations,
        std::vector<ob_fuku_ip_relocations>*		ip_relocations
    );

    void    fuku_obfuscator::lines_correction(std::vector<fuku_instruction>& lines, uint64_t virtual_address);
    void    fuku_obfuscator::handle_jmps(std::vector<fuku_instruction>& lines);
    void    fuku_obfuscator::finalize_jmps(std::vector<fuku_instruction>& lines);

    fuku_instruction * fuku_obfuscator::get_line_by_va(std::vector<fuku_instruction>& lines, uint64_t virtual_address);
    fuku_instruction * fuku_obfuscator::get_line_by_source_va(std::vector<fuku_instruction>& lines, uint64_t virtual_address);
    fuku_instruction * fuku_obfuscator::get_line_by_label_id(unsigned int label_id);
    std::vector<uint8_t>  fuku_obfuscator::lines_to_bin(std::vector<fuku_instruction>&  lines);
public:
    fuku_obfuscator::fuku_obfuscator();
    fuku_obfuscator::~fuku_obfuscator();

    std::vector<uint8_t> fuku_obfuscator::obfuscate_code();

    bool fuku_obfuscator::push_code(
        uint8_t * src, uint32_t src_len,
        uint64_t virtual_address,
        std::vector<ob_fuku_relocation>*	relocations);
public:
    void fuku_obfuscator::set_arch(ob_fuku_arch arch);
    void fuku_obfuscator::set_destination_virtual_address(uint64_t destination_virtual_address);
    void fuku_obfuscator::set_complexity(unsigned int complexity);
    void fuku_obfuscator::set_number_of_passes(unsigned int number_of_passes);

    void fuku_obfuscator::set_association_table(std::vector<ob_fuku_association>*	associations);
    void fuku_obfuscator::set_relocation_table(std::vector<ob_fuku_relocation>* relocations);
    void fuku_obfuscator::set_ip_relocation_table(std::vector<ob_fuku_ip_relocations>* ip_relocations); 
public:  
    ob_fuku_arch   fuku_obfuscator::get_arch();
    uint64_t     fuku_obfuscator::get_destination_virtual_address();
    unsigned int fuku_obfuscator::get_complexity();
    unsigned int fuku_obfuscator::get_number_of_passes();

    std::vector<ob_fuku_association>*    fuku_obfuscator::get_association_table();
    std::vector<ob_fuku_relocation>*     fuku_obfuscator::get_relocation_table();
    std::vector<ob_fuku_ip_relocations>* fuku_obfuscator::get_ip_relocation_table();

public://internal use
    uint32_t fuku_obfuscator::set_label(fuku_instruction& line);
    uint32_t fuku_obfuscator::get_maxlabel();
};

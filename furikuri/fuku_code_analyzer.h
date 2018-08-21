#pragma once

enum fuku_arch {
    fuku_arch_x32,
    fuku_arch_x64
};


struct fuku_code_association {
    uint64_t prev_virtual_address;
    uint64_t virtual_address;
};
struct fuku_code_relocation {
    uint64_t virtual_address;
    uint32_t relocation_id;
};
struct fuku_code_ip_relocation {
    uint64_t    virtual_address;
    uint64_t    destination_virtual_address;
    uint8_t     disp_relocation_offset;
    uint8_t     instruction_size;
};


struct fuku_analyzed_code {
    fuku_arch arch;

    unsigned int label_seed;
    std::vector<uint32_t> labels_cache;
    std::vector<uint32_t> jumps_idx_cache;
    std::vector<uint32_t> rel_idx_cache;
    std::vector<uint32_t> ip_rel_idx_cache;

    linestorage  lines;

    fuku_analyzed_code& operator=(const fuku_analyzed_code& an_code);
    fuku_analyzed_code& operator=(const fuku_code_analyzer& analyzer);

    fuku_analyzed_code();
};

class fuku_code_analyzer {
    fuku_analyzed_code code;

    bool fuku_code_analyzer::analyze_code(
        const uint8_t * src, uint32_t src_len,
        uint64_t virtual_address,
        linestorage&  lines,
        const std::vector<fuku_code_relocation>*	relocations);

    bool fuku_code_analyzer::merge_code(linestorage&  new_lines);

    fuku_instruction * fuku_code_analyzer::get_range_line_by_source_va(linestorage& lines, uint64_t virtual_address);
    fuku_instruction * fuku_code_analyzer::get_direct_line_by_source_va(linestorage& lines, uint64_t virtual_address);

    uint32_t fuku_code_analyzer::set_label(fuku_instruction& line);
public:
    fuku_code_analyzer::fuku_code_analyzer();
    fuku_code_analyzer::fuku_code_analyzer(const fuku_code_analyzer& analyze);
    fuku_code_analyzer::~fuku_code_analyzer();

    fuku_code_analyzer& fuku_code_analyzer::operator=(const fuku_code_analyzer& analyze);

    bool fuku_code_analyzer::push_code(
        const uint8_t * src, uint32_t src_len,
        uint64_t virtual_address,
        const std::vector<fuku_code_relocation>*	relocations);

    bool fuku_code_analyzer::push_code(const linestorage&  code_lines);
public:
    void fuku_code_analyzer::set_arch(fuku_arch arch);
    void fuku_code_analyzer::clear();

public:
    fuku_arch    fuku_code_analyzer::get_arch() const;
    unsigned int fuku_code_analyzer::get_label_seed() const;
    std::vector<uint32_t> fuku_code_analyzer::get_labels_cache() const;
    std::vector<uint32_t> fuku_code_analyzer::get_jumps_idx_cache() const;
    std::vector<uint32_t> fuku_code_analyzer::get_rel_idx_cache() const;
    std::vector<uint32_t> fuku_code_analyzer::get_ip_rel_idx_cache() const;
    linestorage  fuku_code_analyzer::get_lines() const;
};

fuku_instruction * get_line_by_label_id(const fuku_analyzed_code& code, unsigned int label_id);
#pragma once

enum fuku_arch {
    fuku_arch_x32,
    fuku_arch_x64
};

class fuku_code_analyzer {
    fuku_arch arch;

    unsigned int label_seed;
    std::vector<uint32_t> labels_cache;
    std::vector<uint32_t> jumps_idx_cache;
    std::vector<uint32_t> rel_idx_cache;
    std::vector<uint32_t> ip_rel_idx_cache;

    std::vector<fuku_instruction>  lines;

    bool fuku_code_analyzer::analyze_code(
        uint8_t * src, uint32_t src_len,
        uint64_t virtual_address,
        std::vector<fuku_instruction>&  lines,
        const std::vector<ob_fuku_relocation>*	relocations);

    fuku_instruction * fuku_code_analyzer::get_range_line_by_source_va(std::vector<fuku_instruction>& lines, uint64_t virtual_address);
    fuku_instruction * fuku_code_analyzer::get_direct_line_by_source_va(std::vector<fuku_instruction>& lines, uint64_t virtual_address);

    uint32_t fuku_code_analyzer::set_label(fuku_instruction& line);
public:
    fuku_code_analyzer::fuku_code_analyzer(fuku_arch arch);
    fuku_code_analyzer::~fuku_code_analyzer();

    bool fuku_code_analyzer::push_code(
        uint8_t * src, uint32_t src_len,
        uint64_t virtual_address,
        const std::vector<ob_fuku_relocation>*	relocations);

public:
    void fuku_code_analyzer::clear();

public:
    fuku_arch    fuku_code_analyzer::get_arch() const;
    unsigned int fuku_code_analyzer::get_label_seed() const;
    std::vector<fuku_instruction>  fuku_code_analyzer::get_lines() const;
};


#pragma once


class fuku_code_analyzer {
    fuku_code_holder code;

    bool fuku_code_analyzer::analyze_code(
        const uint8_t * src, size_t src_len,
        uint64_t virtual_address, 
        const std::vector<fuku_image_relocation>* relocations,
        fuku_code_holder& analyzed_code);

public:
    fuku_code_analyzer::fuku_code_analyzer();
    fuku_code_analyzer::fuku_code_analyzer(fuku_assambler_arch arch);
    fuku_code_analyzer::fuku_code_analyzer(const fuku_code_analyzer& code_analyzer);
    fuku_code_analyzer::fuku_code_analyzer(const fuku_code_holder& code_holder);

    fuku_code_analyzer::~fuku_code_analyzer();

    fuku_code_analyzer& fuku_code_analyzer::operator=(const fuku_code_analyzer& code_analyzer);
    fuku_code_analyzer& fuku_code_analyzer::operator=(const fuku_code_holder& code_holder);

    bool fuku_code_analyzer::analyze_code(fuku_code_holder& code_holder,
        const uint8_t * src, size_t src_len,
        uint64_t virtual_address,
        const std::vector<fuku_image_relocation>*	relocations);

    bool fuku_code_analyzer::push_code(const fuku_code_holder& code_holder);
    bool fuku_code_analyzer::push_code(const fuku_code_analyzer&  code_analyzer);
    bool fuku_code_analyzer::splice_code(fuku_code_holder& code_holder);
    bool fuku_code_analyzer::splice_code(fuku_code_analyzer& code_holder);
public:
    void fuku_code_analyzer::set_arch(fuku_assambler_arch arch);
    void fuku_code_analyzer::clear();

public:
    fuku_code_holder& get_code();
    const fuku_code_holder& get_code() const;
};
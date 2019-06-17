#pragma once

class psyche_block {
    uint8_t arch;

    uint64_t flags;

    uint32_t block_rva;
    size_t label_idx;

    psy_instructions instructions;
    psy_block_props properties;

public:
    psyche_block(uint8_t arch);
    psyche_block(const psyche_block& block);
    psyche_block(uint8_t arch, uint64_t flags,
        size_t block_rva, size_t label_idx);

    ~psyche_block();


    psyche_block& operator=(const psyche_block& block);

    void add_line(fuku_instruction* line);
public:
    void set_arch(uint8_t arch);

    void set_block_rva(uint32_t rva);
    void set_label_idx(size_t label);

    void set_flags(uint64_t flags);

    void set_instructions(const psy_instructions& instructions);
    void set_properties(const psy_block_props& properties);

public:
    uint8_t get_arch() const;

    uint64_t get_flags() const;

    uint32_t get_block_rva() const;
    size_t get_label_idx() const;

    psy_instructions& get_instructions();
    const psy_instructions& get_instructions() const;

    psy_block_props& get_properties();
    const psy_block_props& get_properties() const;
};


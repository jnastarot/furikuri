#pragma once


class fuku_settings_obfuscation {
    unsigned int complexity;        //number of passes for single line
    unsigned int number_of_passes;  //number of passes for full code
    float junk_chance;   //0.f - 100.f chance of adding junk
    float block_chance;  //0.f - 100.f chance of generation new code graph
    float mutate_chance; //0.f - 100.f chance of mutation line
    uint8_t asm_cfg; //assambler builder flags

public:
    fuku_settings_obfuscation();
    fuku_settings_obfuscation(unsigned int complexity,unsigned int number_of_passes,
    float junk_chance,float block_chance,float mutate_chance,uint8_t asm_cfg);
    fuku_settings_obfuscation(const fuku_settings_obfuscation& obf_set);
    ~fuku_settings_obfuscation();
    fuku_settings_obfuscation& operator=(const fuku_settings_obfuscation& obf_set);
    bool operator==(const fuku_settings_obfuscation& obf_set) const;
public:
    void set_complexity(unsigned int complexity);
    void set_number_of_passes(unsigned int passes);
    void set_junk_chance(float chance);
    void set_block_chance(float chance);
    void set_mutate_chance(float chance);
    void set_asm_cfg(uint8_t flags);

public:
    unsigned int get_complexity() const;
    unsigned int get_number_of_passes() const;
    float   get_junk_chance() const;
    float   get_block_chance() const;
    float   get_mutate_chance() const;
    uint8_t get_asm_cfg() const;

    bool is_null() const;
};


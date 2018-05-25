#pragma once
class fuku_bolrand_map{
    uint32_t parse_context;
    void fuku_bolrand_map::parse_line(uint32_t line_idx, std::vector<std::string> &line);

public:
    fuku_bolrand_map::fuku_bolrand_map(std::vector<std::vector<std::string>>& raw_map, fuku_map& map);
    fuku_bolrand_map::~fuku_bolrand_map();
};


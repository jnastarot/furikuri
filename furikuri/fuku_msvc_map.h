#pragma once
class fuku_msvc_map {
    uint32_t parse_context;
    void fuku_msvc_map::parse_line(uint32_t line_idx, std::vector<std::string> &line);

public:
    fuku_msvc_map::fuku_msvc_map(std::vector<std::vector<std::string>>& raw_map, fuku_map& map);
    fuku_msvc_map::~fuku_msvc_map();
};


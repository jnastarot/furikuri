#pragma once
class fuku_bolrand_map{
    uint32_t parse_context;
    std::vector<fuku_map_segment> segments;
    std::vector<fuku_map_segment> detailed_segments;
    std::vector<fuku_map_public>  publics;

    void fuku_bolrand_map::parse_line(uint32_t line_idx, std::vector<std::string> &line, fuku_map& map);
    void fuku_bolrand_map::post_process_map(fuku_map& map);
public:
    fuku_bolrand_map::fuku_bolrand_map(std::vector<std::vector<std::string>>& raw_map, fuku_map& map);
    fuku_bolrand_map::~fuku_bolrand_map();
};


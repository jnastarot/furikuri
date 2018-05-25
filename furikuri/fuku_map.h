#pragma once

enum fuku_map_segment_class {
    map_segment_class_code,
    map_segment_class_icode,
    map_segment_class_data,
    map_segment_class_bss,
    map_segment_class_tls,
    map_segment_class_unknown
};

enum fuku_map_public_class {
    map_public_class_code,
    map_public_class_data,
    map_public_class_unknown
};

struct fuku_map_segment {
    std::string            segment_name;
    uint32_t               segment_id;
    uint32_t               segment_start;
    uint32_t               segment_length;
    fuku_map_segment_class segment_class;
};

struct fuku_map_public {
    std::string           public_name;
    std::string           public_module_name;
    uint32_t              section_id;
    uint32_t              public_start;
    fuku_map_public_class public_class;
};

struct fuku_map_entry_point {
    uint32_t              section_id;
    uint32_t              public_start;
};

enum fuku_map_result {
    map_resule_ok,
    map_result_error,    //same other error
    map_result_io_error, //error with opening or reading
};


class fuku_msvc_map;
class fuku_bolrand_map;

class fuku_map{
    std::vector<fuku_map_segment> segments;
    std::vector<fuku_map_public>  publics;
    
    fuku_map_entry_point entry_point;
    uint64_t base_address;
    uint32_t time_stamp; //-1 if not present in map file

    fuku_map_result result;

    bool    fuku_map::hexstring_to_value(const std::string& hex_string, uint64_t& value);
    bool    fuku_map::address_string_to_values(const std::string& address_string, uint64_t& section_num, uint64_t& offset);

    std::vector<std::string> fuku_map::get_line_items(const std::string& line);
    void    fuku_map::get_raw_map_file(const std::string& map_text, std::vector<std::vector<std::string>> &raw_map);
public:
    fuku_map::fuku_map();
    fuku_map::~fuku_map();

    fuku_map_result fuku_map::load_from_file(const std::string& map_path);
    fuku_map_result fuku_map::load_from_text(const std::string& map_text);
public:
    fuku_map_result fuku_map::get_result() const;

    const std::vector<fuku_map_segment>& fuku_map::get_segments() const;
    const std::vector<fuku_map_public>&  fuku_map::get_publics() const;

    fuku_map_entry_point fuku_map::get_entry_point() const;
    uint64_t             fuku_map::get_base_address() const;
    uint32_t             fuku_map::get_time_stamp() const;

public:
    friend fuku_msvc_map;
    friend fuku_bolrand_map;
};

#include "fuku_bolrand_map.h"
#include "fuku_msvc_map.h"
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

class fuku_map{
    std::vector<fuku_map_segment> segments;
    std::vector<fuku_map_public>  publics;
    
    fuku_map_entry_point entry_point;
    uint64_t base_address;
    uint32_t time_stamp; //-1 if not present in map file
public:
    fuku_map();
    ~fuku_map();
};


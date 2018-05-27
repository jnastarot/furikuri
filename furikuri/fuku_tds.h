#pragma once

struct fuku_tds_section {
    uint32_t offset;
    uint32_t size;
    uint16_t index;
    uint16_t type;
};

enum fuku_tds_result {
    tds_result_ok,
    tds_result_error
};


struct fuku_tds_linenumbers_block {
    uint32_t segment_id;
    uint32_t block_start;
    uint32_t block_end;

    std::map<uint16_t, uint32_t> line_numbers; //linenumber : segment offset
};

struct fuku_tds_linenumbers {
    std::string file_name;
    std::vector<fuku_tds_linenumbers_block> blocks;
};

struct fuku_tds_function {
    std::string function_name;
    uint32_t segment_id;
    uint32_t function_start;
    uint32_t function_end;
};

struct fuku_tds_data {
    std::string data_name;
    uint32_t segment_id;
    uint32_t data_start;
};

struct fuku_tds_const {
    std::string const_name;
    uint32_t const_size;
    std::vector<uint8_t> value;
};

struct fuku_tds_segment {
    std::string segment_name;
    uint32_t segment_id;
    uint32_t segment_start;
    uint32_t segment_size;
};

class fuku_tds {
    std::vector<std::string> names_pool;
    std::vector<uint8_t> tds_data;

    std::vector<fuku_tds_segment>     segments;
    std::vector<fuku_tds_linenumbers> linenumbers;
    std::vector<fuku_tds_function> functions;
    std::vector<fuku_tds_data>     datas;
    std::vector<fuku_tds_const>    consts;
    
    fuku_tds_result result;

    std::string fuku_tds::get_name_by_id(uint32_t id) const;
    uint32_t fuku_tds::get_id_by_name(const std::string &name) const;

    void fuku_tds::load_names(uint8_t * names_ptr);

    void fuku_tds::ParseModules(const uint8_t * start, const uint8_t * end);
    void fuku_tds::ParseSymbols(const uint8_t * start, const uint8_t * end);
    void fuku_tds::ParseAlignSym(uint8_t * start, uint8_t * end, int moduleIndex);
    void fuku_tds::ParseGlobalSym(uint8_t * start);
    void fuku_tds::parse_src_module(uint8_t * start, uint8_t * end); //linenumbers
public:
    fuku_tds::fuku_tds();
    fuku_tds::~fuku_tds();

    fuku_tds_result fuku_tds::load_from_file(const std::string& tds_path);
    fuku_tds_result fuku_tds::load_from_data(const std::vector<uint8_t>& tds_data);
public:
    
};


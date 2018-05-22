#pragma once

class fuku_graph_spider{
    shibari_module * module;
    fuku_code_list code_list;

    bool fuku_graph_spider::decode_entries(std::vector<uint32_t>& entries,
        std::map<uint32_t, uint8_t>& decoded_items,
        std::vector<uint8_t>& v_module,
        std::vector<_DInst>& di_buf);

    std::vector<uint32_t> fuku_graph_spider::get_code_entries();
    void fuku_graph_spider::link_map(std::map<uint32_t, uint8_t>& decoded_items);
public:
    fuku_graph_spider::fuku_graph_spider(shibari_module * module);
    fuku_graph_spider::~fuku_graph_spider();

    bool fuku_graph_spider::decode_module();
public:
    const fuku_code_list& fuku_graph_spider::get_code_list() const;

};


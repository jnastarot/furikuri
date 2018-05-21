#pragma once

class fuku_graph_spider{
    shibari_module * module;
    std::vector<shibari_module_symbol_info> code_placement;

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
    const std::vector<shibari_module_symbol_info>& fuku_graph_spider::get_code_placement() const;

};


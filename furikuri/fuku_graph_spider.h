#pragma once


class fuku_graph_spider{
    shibari_module * module;

    std::vector<uint32_t> calls_rva;
    std::vector<shibari_module_symbol_info> code_placement;
public:
    fuku_graph_spider::fuku_graph_spider();
    fuku_graph_spider::~fuku_graph_spider();

public:
    const std::vector<shibari_module_symbol_info>& fuku_graph_spider::get_code_placement() const;

};


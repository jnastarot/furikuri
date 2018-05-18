#include "stdafx.h"
#include "fuku_graph_spider.h"


fuku_graph_spider::fuku_graph_spider()
{
}


fuku_graph_spider::~fuku_graph_spider()
{
}


const std::vector<shibari_module_symbol_info>& fuku_graph_spider::get_code_placement() const {
    return code_placement;
}
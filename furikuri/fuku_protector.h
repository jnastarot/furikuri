#pragma once
class fuku_protector {
    ob_fuku_sensitivity settings;
    shibari_module * module;
    std::vector<shibari_module_symbol_info> code_placement;

    void                  fuku_protector::sort_assoc(std::vector<ob_fuku_association>& association);
    ob_fuku_association * fuku_protector::find_assoc(std::vector<ob_fuku_association>& association, uint32_t rva);

    bool    fuku_protector::initialize_zones();
public:
    fuku_protector::fuku_protector(shibari_module * module, const ob_fuku_sensitivity& settings);
    fuku_protector::~fuku_protector();

public:
    bool fuku_protector::protect_module();
};


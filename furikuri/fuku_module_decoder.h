#pragma once

class fuku_module_decoder {
    std::string module_path;
    shibari_module * module;
    fuku_code_list code_list;

    bool fuku_module_decoder::decode_tds(std::vector<uint32_t>& entries, std::map<uint32_t, uint8_t>& decoded_items,
        std::vector<uint8_t>& v_module);
    bool fuku_module_decoder::decode_pdb(std::vector<uint32_t>& entries, std::map<uint32_t, uint8_t>& decoded_items,
        std::vector<uint8_t>& v_module);
    bool fuku_module_decoder::decode_map(std::vector<uint32_t>& entries, std::map<uint32_t, uint8_t>& decoded_items,
        std::vector<uint8_t>& v_module);

    bool fuku_module_decoder::try_decode_debug_info(std::vector<uint32_t>& entries, std::map<uint32_t, uint8_t>& decoded_items,
        std::vector<uint8_t>& v_module);

    bool fuku_module_decoder::decode_entries(std::vector<uint32_t>& entries,
        std::map<uint32_t, uint8_t>& decoded_items,
        std::vector<uint8_t>& v_module,
        std::vector<_DInst>& di_buf);

    std::vector<uint32_t> fuku_module_decoder::get_code_entries();
    void fuku_module_decoder::link_map(std::map<uint32_t, uint8_t>& decoded_items);
public:
    fuku_module_decoder::fuku_module_decoder(shibari_module * module, std::string module_path);
    fuku_module_decoder::~fuku_module_decoder();

    bool fuku_module_decoder::decode_module();
};


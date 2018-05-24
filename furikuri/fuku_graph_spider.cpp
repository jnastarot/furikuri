#include "stdafx.h"
#include "fuku_graph_spider.h"


fuku_graph_spider::fuku_graph_spider(shibari_module * module)
    :module(module){}


fuku_graph_spider::~fuku_graph_spider()
{
}



bool fuku_graph_spider::decode_module() {
    code_list.code_placement.clear();
    code_list.func_starts.clear();

    if (!this->module) { return false; }


    std::vector<uint32_t> entries = get_code_entries();
    std::map<uint32_t, uint8_t> decoded_items;
    std::vector<uint8_t> v_module;
    std::vector<_DInst> distorm_instructions;
    
    code_list.func_starts = entries;

    if (pe_image_io(this->module->get_image()).read(v_module,
        this->module->get_image().get_last_section()->get_virtual_address() +
        this->module->get_image().get_last_section()->get_virtual_size()) == enma_io_code::enma_io_data_not_present) {

        return false;
    }

    distorm_instructions.resize(v_module.size());

    while (entries.size()) {
        if (!decode_entries(entries, decoded_items, v_module, distorm_instructions)) {
            return false;
        }
    }

    link_map(decoded_items);


    return true;
}


const fuku_code_list& fuku_graph_spider::get_code_list() const {
    return code_list;
}

void fuku_graph_spider::link_map(std::map<uint32_t, uint8_t>& decoded_items) {

    for (auto& item : decoded_items) {

        if (!code_list.code_placement.size()) {
            code_list.code_placement.push_back({ item.first , item.second });
            continue;
        }
        else {
            auto& zone = code_list.code_placement[code_list.code_placement.size() - 1];

            if (zone.symbol_info_rva <= item.first &&
                zone.symbol_info_rva + zone.symbol_info_size >= item.first) {

                zone.symbol_info_size = 
                    ((item.first + item.second) - zone.symbol_info_rva);
            }
            else {
                code_list.code_placement.push_back({ item.first , item.second });
            }
        }
    }
}


std::vector<uint32_t> fuku_graph_spider::get_code_entries() {
    std::vector<uint32_t> entries;
    pe_image_io image_io(this->module->get_image());

    entries.push_back(this->module->get_image().get_entry_point());                     //entry point

    for (auto& entry_point_ex : this->module->get_module_entrys()) {
        entries.push_back(entry_point_ex.entry_point_rva);
    }


    for (auto& export_item : this->module->get_module_exports().get_export_items()) {   //exports
        if (image_io.is_executable_rva(export_item.get_rva()) &&
            !image_io.is_writeable_rva(export_item.get_rva())) {
            entries.push_back(export_item.get_rva());
        }
    }

    for (auto& tls_item : this->module->get_image_tls().get_callbacks()) {              //tls callbacks
        if (tls_item.rva_callback) {
            entries.push_back(tls_item.rva_callback);
        }
    }

    if (this->module->get_image().is_x32_image()) {
        for (auto& se_handler : this->module->get_image_load_config().get_se_handlers()) { //seh handlers
            entries.push_back(se_handler);
        }
    }

    for (auto& cf_guard : this->module->get_image_load_config().get_guard_cf_functions()) { //cf functions
        entries.push_back(cf_guard);
    }


    return entries;
}


bool fuku_graph_spider::decode_entries(std::vector<uint32_t>& entries, std::map<uint32_t, uint8_t>& decoded_items,
    std::vector<uint8_t>& v_module,
    std::vector<_DInst>& di_buf) {

    uint32_t entry_rva = entries[0];
    entries.erase(entries.begin());

    
    if (decoded_items.find(entry_rva) != decoded_items.end()) {
        return true;
    }
    
    _CodeInfo code_info = { entry_rva,0, &v_module[entry_rva] , int(v_module.size() - entry_rva),
        this->module->get_image().is_x32_image() ? _DecodeType::Decode32Bits : _DecodeType::Decode64Bits,
        DF_STOP_ON_RET | DF_STOP_ON_INT
    };

    unsigned int instructions_number = 0;
    _DecodeResult di_result = distorm_decompose64(&code_info, di_buf.data(), v_module.size() - entry_rva, &instructions_number);

    if (di_result != _DecodeResult::DECRES_SUCCESS) {
        return false;
    }


    for (uint32_t di_idx = 0; di_idx < instructions_number; di_idx++) {
        decoded_items[di_buf[di_idx].addr] = di_buf[di_idx].size;
    }

    for (uint32_t di_idx = 0; di_idx < instructions_number; di_idx++) {
        switch (di_buf[di_idx].opcode) {

            case I_CALL: {
                if (v_module[di_buf[di_idx].addr] == 0xE8) {
                    auto item = std::find(code_list.func_starts.begin(), code_list.func_starts.end(), INSTRUCTION_GET_TARGET(&di_buf[di_idx]));

                    if (item == code_list.func_starts.end()) {
                        code_list.func_starts.push_back(INSTRUCTION_GET_TARGET(&di_buf[di_idx]));
                    }

                    if (decoded_items.find(INSTRUCTION_GET_TARGET(&di_buf[di_idx])) == decoded_items.end()) {
                        entries.push_back(INSTRUCTION_GET_TARGET(&di_buf[di_idx]));
                    }
                }
                break;
            }

            case I_JMP: {                                                           //uncondition jump
                if (v_module[di_buf[di_idx].addr] == 0xE9 || v_module[di_buf[di_idx].addr] == 0xEB) {

                    if (decoded_items.find(INSTRUCTION_GET_TARGET(&di_buf[di_idx])) == decoded_items.end()) {
                        entries.push_back(INSTRUCTION_GET_TARGET(&di_buf[di_idx]));
                    }
                }
                break;
            }

            case I_JA:case I_JAE:case I_JB:case I_JBE:case I_JG:case I_JGE:         //condition jumps
            case I_JL: case I_JLE: case I_JNO: case I_JNP: case I_JNS: case I_JNZ: case I_JO: 
            case I_JP:  case I_JS: case I_JZ:
            case I_JCXZ:case I_JECXZ:case I_JRCXZ: {


                if (decoded_items.find(INSTRUCTION_GET_TARGET(&di_buf[di_idx])) == decoded_items.end()) {
                    entries.push_back(INSTRUCTION_GET_TARGET(&di_buf[di_idx]));
                }
                break;
            }
            default:break;
        }
    }

    return true;
}
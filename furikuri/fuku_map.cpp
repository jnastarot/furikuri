#include "stdafx.h"
#include "fuku_map.h"



fuku_map::fuku_map() {
    entry_point = {0, 0};
    base_address = 0;
    time_stamp = -1;
    result = fuku_map_result::map_resule_ok;
    type   = fuku_map_type::map_type_unknown;
}

fuku_map::~fuku_map()
{
}


fuku_map_result fuku_map::load_from_file(const std::string& map_path) {
    entry_point = { 0, 0 };
    base_address = 0;
    time_stamp = -1;
    result = fuku_map_result::map_resule_ok;

    std::string content;

    FILE* hfile;

    fopen_s(&hfile,map_path.c_str(), "rb");

    if (hfile != nullptr) {

        fseek(hfile, 0, SEEK_END);
        size_t file_size = ftell(hfile);
        fseek(hfile, 0, SEEK_SET);

        content.reserve(file_size);
        content.resize(file_size);

        if (fread((void*)content.data(), file_size, 1, hfile)) {
            result = load_from_text(content);
        }
        else {
            result = fuku_map_result::map_result_io_error;
        }

        fclose(hfile);
    }
    else {
        result = fuku_map_result::map_result_io_error;
    }

    return result;
}

fuku_map_result fuku_map::load_from_text(const std::string& map_text) {

    std::vector<std::vector<std::string>> raw_map;
    get_raw_map_file(map_text, raw_map);

    uint32_t bolrand_signs = 0;
    uint32_t msvc_signs = 0;

    for (auto& map_line : raw_map) {

        if ( (map_line.size() == 4 && map_line[0] == "entry" && map_line[1] == "point" && map_line[2] == "at") ||
             (map_line.size() == 5 && map_line[0] == "Preferred" && map_line[1] == "load" && map_line[2] == "address" && map_line[3] == "is") ||
             (map_line.size() >= 3 && map_line[0] == "Timestamp" && map_line[1] == "is") ||
             (map_line.size() == 6 && map_line[0] == "Address" && map_line[1] == "Publics" && map_line[2] == "by" && map_line[3] == "Value"
                && map_line[4] == "Rva+Base" && map_line[5] == "Lib:Object") ||
             (map_line.size() == 2 && map_line[0] == "Static" && map_line[1] == "symbols")
            ) {

            msvc_signs++;
        }
       
        if ((map_line.size() == 5 && map_line[0] == "Program" && map_line[1] == "entry" && map_line[2] == "point" && map_line[3] == "at" ) ||
            (map_line.size() == 4 && map_line[0] == "Preferred" && map_line[1] == "load" && map_line[2] == "address" && map_line[3] == "is") ||
            (map_line.size() == 4 && map_line[0] == "Address" && map_line[1] == "Publics" && map_line[2] == "by" && map_line[3] == "Name") ||
            (map_line.size() == 4 && map_line[0] == "Detailed" && map_line[1] == "map" && map_line[2] == "of" && map_line[3] == "segments") ||
            (map_line.size() == 3 && map_line[0] == "Bound" && map_line[1] == "resource" && map_line[2] == "files")
            ) {

            bolrand_signs++;
        }
    }

    if (bolrand_signs > msvc_signs) {
        fuku_bolrand_map(raw_map, *this);
        type = fuku_map_type::map_type_bolrand;
    }
    else {
        fuku_msvc_map(raw_map, *this);
        type = fuku_map_type::map_type_msvc;
    }



    return result;
}


fuku_map_result fuku_map::get_result() const {
    return result;
}

fuku_map_type   fuku_map::get_type() const {
    return type;
}

const std::vector<fuku_map_segment>& fuku_map::get_segments() const {
    return segments;
}
const std::vector<fuku_map_public>&  fuku_map::get_publics() const {
    return publics;
}

fuku_map_entry_point fuku_map::get_entry_point() const {
    return entry_point;
}

uint64_t             fuku_map::get_base_address() const {
    return base_address;
}

uint32_t             fuku_map::get_time_stamp() const {
    return time_stamp;
}


std::vector<std::string> fuku_map::get_line_items(const std::string& line) {
    std::vector<std::string> items;
    std::istringstream str_stream(line);

    for (std::string word; str_stream >> word;) {
        items.push_back(word);
    }

    return items;
}

void fuku_map::get_raw_map_file(const std::string& map_text, std::vector<std::vector<std::string>> &raw_map) {
    raw_map.clear();

    std::istringstream i(map_text);

    for (std::string line; !i.eof() && std::getline(i, line);) {
        if (line.length() == 0) { continue; }
        if (line.substr(0, 1).compare("\x20") == 0) { line = line.substr(1); }
        if (line.substr(line.length() - 1).compare("\r") == 0) { line.pop_back(); }

        std::vector<std::string> linedata = get_line_items(line);
        if (linedata.size() == 0) { continue; }

        raw_map.push_back(linedata);
    }
}

 bool fuku_map::hexstring_to_value(const std::string& hex_string, uint64_t& value) {
    bool was_init_first = false;
    value = 0;
    for (size_t i = 0; i < hex_string.length(); i++) {
        if (hex_string[i] >= '0' && hex_string[i] <= '9') {
            value *= 0x10;
            value += (hex_string[i] - '0');
            was_init_first = true;
        }
        else if (hex_string[i] >= 'a' && hex_string[i] <= 'f') {
            value *= 0x10;
            value += (0xA + (hex_string[i] - 'a'));
            was_init_first = true;
        }
        else if (hex_string[i] >= 'A' && hex_string[i] <= 'F') {
            value *= 0x10;
            value += (0xA + (hex_string[i] - 'A'));
            was_init_first = true;
        }
        else {
            return was_init_first;
        }
    }

    return was_init_first;
}

bool fuku_map::address_string_to_values(const std::string& address_string, uint64_t& section_num, uint64_t& offset) {

    if (hexstring_to_value(address_string.substr(0, 4), section_num) && hexstring_to_value(address_string.substr(5), offset)) {
        return true;
    }

    return false;
}
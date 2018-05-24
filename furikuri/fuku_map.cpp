#include "stdafx.h"
#include "fuku_map.h"


inline bool hexstring_to_value(std::string& hex_string, uint64_t& value);
inline bool address_string_to_values(std::string& address_string, uint64_t& section_num, uint64_t& offset);
std::vector<std::string> get_line_items(std::string& line);
void get_raw_map_file(std::string& map_text, std::vector<std::vector<std::string>> &raw_map);

#include "fuku_bolrand_map.h"
#include "fuku_msvc_map.h"


fuku_map::fuku_map()
{
}


fuku_map::~fuku_map()
{
}


std::vector<std::string> get_line_items(std::string& line) {
    std::vector<std::string> items;
    std::istringstream str_stream(line);

    for (std::string word; str_stream >> word;) {
        items.push_back(word);
    }

    return items;
}

void get_raw_map_file(std::string& map_text, std::vector<std::vector<std::string>> &raw_map) {
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

inline bool hexstring_to_value(std::string& hex_string, uint64_t& value) {
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

inline bool address_string_to_values(std::string& address_string, uint64_t& section_num, uint64_t& offset) {

    if (hexstring_to_value(address_string.substr(0, 4), section_num) && hexstring_to_value(address_string.substr(5), offset)) {
        return true;
    }

    return false;
}
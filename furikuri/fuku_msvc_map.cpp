#include "stdafx.h"
#include "fuku_msvc_map.h"

enum msvc_map_context {
    msvc_map_context_none,
    msvc_map_context_segment,
    msvc_map_context_public,
};


fuku_msvc_map::fuku_msvc_map(std::vector<std::vector<std::string>>& raw_map, fuku_map& map) {

    this->parse_context = msvc_map_context_none;

    uint32_t line_idx = 0;
    for (auto &line : raw_map) {

        parse_line(line_idx, line, map);

        line_idx++;
    }
}


fuku_msvc_map::~fuku_msvc_map() {};


void fuku_msvc_map::parse_line(uint32_t line_idx, std::vector<std::string> &line, fuku_map& map) {

    if (this->parse_context == msvc_map_context_none) {
        if (line.size() == 4 && line[0] == "entry" && line[1] == "point" && line[2] == "at") {
            map.address_string_to_values(line[3], map.entry_point.segment_id, map.entry_point.public_start);
            return;
        }
        else if ((line.size() >= 4 && line[0] == "Address" && line[1] == "Publics" && line[2] == "by" && line[3] == "Value") ||
            (line.size() >= 2 && line[0] == "Static" && line[1] == "symbols")
            ) {
            this->parse_context = msvc_map_context_public;
            return;

        }
        else if (line.size() == 4 && line[0] == "Start" && line[1] == "Length" && line[2] == "Name" && line[3] == "Class") {
            this->parse_context = msvc_map_context_segment;
            return;
        }
        else if (line.size() == 5 && line[0] == "Preferred" && line[1] == "load" && line[2] == "address" && line[3] == "is") {
            map.hexstring_to_value(line[4], map.base_address);
            return;
        }
        else if (line.size() >= 3 && line[0] == "Timestamp" && line[1] == "is") {
            uint64_t lont_ts;
            map.hexstring_to_value(line[2], lont_ts);

            map.time_stamp = uint32_t(lont_ts);
            return;
        }
    }
    else if (this->parse_context == msvc_map_context_segment) {
        if (line.size() == 4) {
            fuku_map_segment segment;
            if (map.address_string_to_values(line[0], segment.segment_id, segment.segment_start) &&
                map.hexstring_to_value(line[1], segment.segment_length)) {

                segment.segment_name = line[2];

                if (line[3] == "CODE") {
                    segment.segment_class = fuku_map_segment_class::map_segment_class_code;
                }
                else if (line[3] == "DATA") {
                    segment.segment_class = fuku_map_segment_class::map_segment_class_data;
                }
                else {
                    segment.segment_class = fuku_map_segment_class::map_segment_class_unknown;
                }

                map.segments.push_back(segment);
                return;
            }
            else {
                this->parse_context = msvc_map_context_none;
                parse_line(line_idx, line, map);
            }
        }
        else {
            this->parse_context = msvc_map_context_none;
            parse_line(line_idx, line, map);
            return;
        }
    }
    else if (this->parse_context == msvc_map_context_public) {

        if (line.size() >= 4) {
            fuku_map_public item;

            if (map.address_string_to_values(line[0], item.segment_id, item.public_start)) {

                if (!item.segment_id) {
                    if (line[1] == "___ImageBase") {
                        map.hexstring_to_value(line[2], map.base_address);
                    }
                    return;
                }

                item.public_class = (line[3].compare("f") == 0) ? 
                    fuku_map_public_class::map_public_class_code : fuku_map_public_class::map_public_class_data;

                item.public_name = line[1];
                item.public_module_name = line[line.size() - 1];

                map.publics.push_back(item);
                return;
            }
            else {
                this->parse_context = msvc_map_context_none;
                parse_line(line_idx, line, map);
                return;
            }
        }
        else {
            this->parse_context = msvc_map_context_none;
            parse_line(line_idx, line, map);
            return;
        }
    }

    this->parse_context = msvc_map_context_none;
}
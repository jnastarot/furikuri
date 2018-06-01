#include "stdafx.h"
#include "fuku_bolrand_map.h"


enum bolrand_map_context {
    bolrand_map_context_none,
    bolrand_map_context_segment,
    bolrand_map_context_detailed_segment,
    bolrand_map_context_public,
};

fuku_bolrand_map::fuku_bolrand_map(std::vector<std::vector<std::string>>& raw_map, fuku_map& map) {

    this->parse_context = bolrand_map_context_none;

    uint32_t line_idx = 0;
    for (auto &line : raw_map) {

        parse_line(line_idx, line, map);

        line_idx++;
    }

    post_process_map(map);
}

fuku_bolrand_map::~fuku_bolrand_map() {

}

void fuku_bolrand_map::parse_line(uint32_t line_idx, std::vector<std::string> &line, fuku_map& map) {

    if (this->parse_context == bolrand_map_context_none) {
        if (line.size() == 5 && line[0] == "Program" && line[1] == "entry" && line[2] == "point" && line[3] == "at") {
            map.address_string_to_values(line[4], map.entry_point.segment_id, map.entry_point.public_start);
            return;
        }
        else if ((line.size() >= 4 && line[0] == "Address" && line[1] == "Publics" && line[2] == "by" && line[3] == "Value") ||
            (line.size() >= 2 && line[0] == "Static" && line[1] == "symbols")
            ) {
            this->parse_context = bolrand_map_context_public;
            return;

        }
        else if (line.size() == 4 && line[0] == "Start" && line[1] == "Length" && line[2] == "Name" && line[3] == "Class") {
            this->parse_context = bolrand_map_context_segment;
            return;
        }
        else if (line.size() == 4 && line[0] == "Detailed" && line[1] == "map" && line[2] == "of" && line[3] == "segments") {
            this->parse_context = bolrand_map_context_detailed_segment;
            return;
        }
    }
    else if (this->parse_context == bolrand_map_context_segment) {
        if (line.size() == 4) {
            fuku_map_segment segment;
            if (map.address_string_to_values(line[0], segment.segment_id, segment.segment_start) &&
                map.hexstring_to_value(line[1], segment.segment_length)) {

                if (line[3] == "CODE") {
                    segment.segment_class = fuku_map_segment_class::map_segment_class_code;
                }
                else if (line[3] == "ICODE") {
                    segment.segment_class = fuku_map_segment_class::map_segment_class_icode;
                }
                else if (line[3] == "DATA") {
                    segment.segment_class = fuku_map_segment_class::map_segment_class_data;
                }
                else if (line[3] == "BSS") {
                    segment.segment_class = fuku_map_segment_class::map_segment_class_bss;
                }
                else if (line[3] == "TLS") {
                    segment.segment_class = fuku_map_segment_class::map_segment_class_tls;
                }
                else {
                    segment.segment_class = fuku_map_segment_class::map_segment_class_unknown;
                }

                segment.segment_name = line[2];
               
                segments.push_back(segment);
                return;
            }
            else {
                this->parse_context = bolrand_map_context_none;
                parse_line(line_idx, line, map);
                return;
            }
        }
        else {
            this->parse_context = bolrand_map_context_none;
            parse_line(line_idx, line, map);
            return;
        }
    }
    else if (this->parse_context == bolrand_map_context_detailed_segment) {
        if (line.size() == 7) {
            fuku_map_segment segment;
            if (map.address_string_to_values(line[0], segment.segment_id, segment.segment_start) &&
                map.hexstring_to_value(line[1], segment.segment_length)) {
                
                segment.segment_name = std::string(&line[5].c_str()[2]);
                segment.segment_class = fuku_map_segment_class::map_segment_class_unknown;

                detailed_segments.push_back(segment);
                return;
            }
        }
        else {
            this->parse_context = bolrand_map_context_none;
            parse_line(line_idx, line, map);
            return;
        }
    }
    else if (this->parse_context == bolrand_map_context_public) {
        if (line.size() == 2) {
            fuku_map_public item;
            if (map.address_string_to_values(line[0], item.segment_id, item.public_start)) {

                if (line[1] == "SysInit.__ImageBase"){
                    if (segments.size() >= item.segment_id) {
                        map.base_address = uint32_t(segments[item.segment_id - 1].segment_start) + uint32_t(item.public_start);
                        return;
                    }
                }
           
                item.public_name = line[1];

                publics.push_back(item);
                return;
            }
        }
        else {
            this->parse_context = bolrand_map_context_none;
            parse_line(line_idx, line, map);
            return;
        }
    }

    this->parse_context = bolrand_map_context_none;
}

void fuku_bolrand_map::post_process_map(fuku_map& map) {
   
    for (auto& _pub : publics) {
        for (auto& detailed_segment : detailed_segments) {
            if (_pub.segment_id == detailed_segment.segment_id &&
                _pub.public_start >= detailed_segment.segment_start && 
                _pub.public_start < detailed_segment.segment_start + detailed_segment.segment_length) {

                _pub.public_module_name = detailed_segment.segment_name;
            }
        }
    }

    for (auto& pub : publics) {
        if (segments[pub.segment_id-1].segment_class == map_segment_class_code) {
            if (pub.public_name.find("..")) {
                if (pub.public_name.find("...")) {
                    pub.public_class = fuku_map_public_class::map_public_class_code;
                }
                else {
                    pub.public_class = fuku_map_public_class::map_public_class_data;
                }
            }
            else {
                pub.public_class = fuku_map_public_class::map_public_class_code;
            }
        }
    }

    map.publics = publics;
    map.segments = segments;
}
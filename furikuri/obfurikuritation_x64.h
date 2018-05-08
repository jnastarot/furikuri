#pragma once

void fuku_x64_junk(std::vector<obfurikuristruction>& lines, unsigned int current_line_idx,
    std::vector<obfurikuristruction>& out_lines);


bool fukutate_add_x64(std::vector<obfurikuristruction>& lines, unsigned int current_line_idx,std::vector<obfurikuristruction>& out_lines);
bool fukutate_sub_x64(std::vector<obfurikuristruction>& lines, unsigned int current_line_idx,std::vector<obfurikuristruction>& out_lines);


void obfurikuriator::obfurikuritation_x64(std::vector<obfurikuristruction>& lines, unsigned int current_line_idx,
    std::vector<obfurikuristruction>& out_lines) {

    if (FUKU_GET_CHANCE(FUKU_GENERATE_JUNK_CHANCE)) {
        fuku_x64_junk(lines, current_line_idx, out_lines);
    }

    if (FUKU_GET_CHANCE(FUKU_MUTATE_LINE_CHANCE)) {
        switch (lines[current_line_idx].get_type()) {

        case I_ADD: {
            if (!fukutate_add_x64(lines, current_line_idx , out_lines) ) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        case I_SUB: {
            if (!fukutate_sub_x64(lines, current_line_idx, out_lines)) {
                out_lines.push_back(lines[current_line_idx]);
            }
            break;
        }

        default: {
            out_lines.push_back(lines[current_line_idx]);
            break;
        }
        }
    }
    else {
        out_lines.push_back(lines[current_line_idx]);
    }
}


bool fukutate_add_x64(std::vector<obfurikuristruction>& lines, unsigned int current_line_idx,
    std::vector<obfurikuristruction>& out_lines) {


    return false;
}
bool fukutate_sub_x64(std::vector<obfurikuristruction>& lines, unsigned int current_line_idx,
    std::vector<obfurikuristruction>& out_lines) {

    return false;
}

void fuku_x64_junk(std::vector<obfurikuristruction>& lines, unsigned int current_line_idx,
    std::vector<obfurikuristruction>& out_lines) {

    

}
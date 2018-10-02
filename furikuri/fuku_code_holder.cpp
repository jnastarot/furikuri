#include "stdafx.h"
#include "fuku_code_holder.h"


fuku_code_holder::fuku_code_holder()
    :arch(fuku_arch::fuku_arch_unknown), labels_count(0){}

fuku_code_holder::fuku_code_holder(fuku_arch arch)
    :arch(arch), labels_count(0) {}

fuku_code_holder::fuku_code_holder(const fuku_code_holder& code_holder) {
    this->operator=(code_holder);
}

fuku_code_holder::fuku_code_holder(const fuku_code_analyzer& code_analyzer) {
    this->operator=(code_analyzer);
}

fuku_code_holder::~fuku_code_holder() {

}


fuku_code_holder& fuku_code_holder::operator=(const fuku_code_holder& code_holder) {
    this->arch = code_holder.arch;
    this->labels_count = code_holder.labels_count;
    this->labels = code_holder.labels;
    this->relocations = code_holder.relocations;
    this->rip_relocations = code_holder.rip_relocations;
    this->original_lines = code_holder.original_lines;
    this->lines = code_holder.lines;

    if (labels_count) {
     
        std::vector<fuku_instruction* > labels_cache;
        labels_cache.resize(labels_count);

        for (auto& line : lines) {

            if (line.get_label_idx() != -1) {
                labels_cache[line.get_label_idx()] = &line;
            }
        }



        for (size_t label_idx = 0; label_idx < labels.size(); label_idx++) {

            if (labels[label_idx].has_linked_instruction) {
                labels[label_idx].instruction = labels_cache[label_idx];
            }
        }

    }


    return *this;
}

fuku_code_holder& fuku_code_holder::operator=(const fuku_code_analyzer& code_analyzer) {

    operator=(code_analyzer.get_code());

    return *this;
}

void   fuku_code_holder::update_origin_idxs() {

    original_lines.clear();

    for (auto& line : lines) {     
        if (line.get_source_virtual_address() != -1) {
            original_lines.push_back(&line);
        }
    }

    std::sort(original_lines.begin(), original_lines.end(), [&, this](const fuku_instruction * l_line, const fuku_instruction * r_line) {
        return l_line->get_source_virtual_address() < r_line->get_source_virtual_address();
    });
}

size_t fuku_code_holder::create_label(fuku_instruction* line) {

    if (line->get_label_idx() == -1) {

        line->set_label_idx(labels_count);
        
        fuku_code_label label;
        label.has_linked_instruction = 1;
        label.instruction = line;

        labels.push_back(label);
        labels_count++;
    }

    return line->get_label_idx();
}

size_t fuku_code_holder::create_label(uint64_t dst_address) {

    fuku_code_label label;
    label.has_linked_instruction = 0;
    label.dst_address = dst_address;

    labels.push_back(label);
    labels_count++;

    return labels_count - 1;
}

size_t fuku_code_holder::create_relocation(uint8_t offset, uint64_t dst_address, uint32_t relocation_id) {

    relocations.push_back({ relocation_id , offset , create_label(dst_address) });

    return relocations.size() - 1;
}

size_t fuku_code_holder::create_relocation(uint8_t offset, fuku_instruction* line, uint32_t relocation_id) {

    relocations.push_back({ relocation_id , offset , create_label(line) });

    return relocations.size() - 1;
}

size_t fuku_code_holder::create_rip_relocation(uint8_t offset, uint64_t dst_address) {

    
    rip_relocations.push_back({ offset , create_label(dst_address) });

    return rip_relocations.size() - 1;
}

size_t fuku_code_holder::create_rip_relocation(uint8_t offset, fuku_instruction* line) {

    rip_relocations.push_back({ offset , create_label(line) });

    return rip_relocations.size() - 1;
}

fuku_instruction& fuku_code_holder::add_line() {
    lines.push_back(fuku_instruction());

    return lines.back();
}


void fuku_code_holder::clear() {
    this->labels_count = 0;
    this->labels.clear();
    this->relocations.clear();
    this->rip_relocations.clear();
    this->original_lines.clear();
    this->lines.clear();
}

fuku_instruction * fuku_code_holder::get_range_line_by_source_va(uint64_t virtual_address) {


    if (original_lines.size()) {

        if (original_lines[0]->get_source_virtual_address() <= virtual_address &&

           (original_lines[original_lines.size() - 1]->get_source_virtual_address() + 
               original_lines[original_lines.size() - 1]->get_op_length()) >= virtual_address) {

            size_t left = 0;
            size_t right = original_lines.size();
            size_t mid = 0;

            while (left < right) {
                mid = left + (right - left) / 2;

                if (original_lines[mid]->get_source_virtual_address() <= virtual_address &&
                    original_lines[mid]->get_source_virtual_address() + original_lines[mid]->get_op_length() > virtual_address) {

                    return original_lines[mid];
                }
                else if (original_lines[mid]->get_source_virtual_address() > virtual_address) {
                    right = mid;
                }
                else {
                    left = mid + 1;
                }
            }
    
        }
    }

    return 0;
}

fuku_instruction * fuku_code_holder::get_direct_line_by_source_va(uint64_t virtual_address) {

    if (original_lines.size()) {

        if (original_lines[0]->get_source_virtual_address() <= virtual_address &&
            original_lines[original_lines.size() - 1]->get_source_virtual_address() >= virtual_address) {

            size_t left = 0;
            size_t right = original_lines.size();
            size_t mid = 0;

            while (left < right) {
                mid = left + (right - left) / 2;

                if (original_lines[mid]->get_source_virtual_address() == virtual_address) {
                    return original_lines[mid];
                }
                else if (original_lines[mid]->get_source_virtual_address() > virtual_address) {
                    right = mid;
                }
                else {
                    left = mid + 1;
                }
            }

        }
    }

    return 0;
}


void fuku_code_holder::set_arch(fuku_arch arch) {
    this->arch = arch;
}

void fuku_code_holder::set_labels_count(size_t labels_count) {
    this->labels_count = labels_count;
}

void fuku_code_holder::set_labels(const std::vector<fuku_code_label>& labels) {
    this->labels = labels;
}

void fuku_code_holder::set_relocations(const std::vector<fuku_code_relocation>& relocs) {
    this->relocations = relocs;
}

void fuku_code_holder::set_rip_relocations(const std::vector<fuku_code_rip_relocation>& rip_relocs) {
    this->rip_relocations = rip_relocs;
}

void fuku_code_holder::set_original_lines_idxs(const std::vector<fuku_instruction *>& original_lines) {
    this->original_lines = original_lines;
}

void fuku_code_holder::set_lines(const linestorage& lines) {
    this->lines = lines;
}

std::vector<fuku_code_label>& fuku_code_holder::get_labels() {
    return this->labels;
}

std::vector<fuku_code_relocation>& fuku_code_holder::get_relocations() {
    return this->relocations;
}

std::vector<fuku_code_rip_relocation>& fuku_code_holder::get_rip_relocations() {
    return this->rip_relocations;
}

std::vector<fuku_instruction *>& fuku_code_holder::get_original_lines() {
    return this->original_lines;
}

linestorage&  fuku_code_holder::get_lines() {
    return this->lines;
}


fuku_arch fuku_code_holder::get_arch() const {
    return this->arch;
}

size_t fuku_code_holder::get_labels_count() const {
    return this->labels_count;
}

const std::vector<fuku_code_label>& fuku_code_holder::get_labels() const {
    return this->labels;
}

const std::vector<fuku_code_relocation>& fuku_code_holder::get_relocations() const {
    return this->relocations;
}

const std::vector<fuku_code_rip_relocation>& fuku_code_holder::get_rip_relocations() const {
    return this->rip_relocations;
}

const std::vector<fuku_instruction *>& fuku_code_holder::get_original_lines() const {
    return this->original_lines;
}

const linestorage&  fuku_code_holder::get_lines() const {
    return this->lines;
}

std::vector<uint8_t> dump_lines(fuku_code_holder&  code_holder) {

    std::vector<uint8_t> lines_dump;
    size_t dump_size = 0;

    /*
    for (size_t line_idx = 0; line_idx < lines.size(); line_idx++) { dump_size += lines[line_idx].get_op_length(); }
    lines_dump.resize(dump_size);

    size_t opcode_caret = 0;
    for (auto &line : lines) {
        memcpy(&lines_dump.data()[opcode_caret], line.get_op_code(), line.get_op_length());
        opcode_caret += line.get_op_length();
    }
    */

    return lines_dump;
}
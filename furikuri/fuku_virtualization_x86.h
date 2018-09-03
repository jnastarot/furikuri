#pragma once
class fuku_virtualization_x86 :
    public fuku_virtualizer {

    vm_linestorage lines;

    std::vector<fuku_vm_instruction> create_operand_reg(uint8_t reg, bool ptr);
    std::vector<fuku_vm_instruction> create_operand_disp(uint32_t disp);     // [disp/r]
    std::vector<fuku_vm_instruction> create_operand_reg_disp(uint8_t base, uint32_t disp); // [base + disp/r]
    std::vector<fuku_vm_instruction> create_operand_sib(uint8_t base, uint8_t index, uint8_t scale, uint32_t disp);// [base + index*scale + disp/r]
    std::vector<fuku_vm_instruction> create_operand_sib(uint8_t index, uint8_t scale, uint32_t disp);// [index*scale + disp/r]

    void get_operands(const _DInst& inst,const fuku_instruction& line, std::vector<fuku_vm_instruction>& operands);
    uint8_t get_ext_code(const _DInst& inst);

    void post_process_lines();
public:
    fuku_virtualization_x86();
    ~fuku_virtualization_x86();

    fuku_vm_result fuku_virtualization_x86::build_bytecode(fuku_analyzed_code& code, 
        std::vector<fuku_code_relocation>& relocation_table, std::vector<fuku_code_association>& association_table, 
        uint64_t destination_virtual_address);

    std::vector<uint8_t> fuku_virtualization_x86::create_vm_jumpout(uint64_t src_address, uint64_t dst_address) const;
    std::vector<uint8_t> fuku_virtualization_x86::get_bytecode() const;

    fuku_arch fuku_virtualization_x86::get_target_arch() const;
};


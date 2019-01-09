#pragma once


class fuku_asm_x64{
    uint8_t bytecode[16];
    uint8_t length;

    uint8_t displacment_offset;
    uint8_t immediate_offset;

    uint8_t short_cfg;
    
    void clear_space();

    void emit_b(uint8_t x);
    void emit_w(uint16_t x);
    void emit_dw(uint32_t x);
    void emit_qw(uint64_t x);

    void emit_immediate_b(fuku_immediate& src);
    void emit_immediate_w(fuku_immediate& src);
    void emit_immediate_dw(fuku_immediate& src);
    void emit_immediate_qw(fuku_immediate& src);

    void emit_rex(bool x64bit_size, bool x64ext_reg, bool x64ext_index, bool x64ext_base);
    void emit_rex_64();
    void emit_rex_64(fuku_register reg, fuku_register rm_reg);
    void emit_rex_64(fuku_register reg, const fuku_operand& op);
    void emit_rex_64(fuku_register rm_reg);
    void emit_rex_64(const fuku_operand& op);
    void emit_rex_32(fuku_register reg, fuku_register rm_reg);
    void emit_rex_32(fuku_register reg, const fuku_operand& op);
    void emit_rex_32(fuku_register rm_reg);
    void emit_rex_32(const fuku_operand& op);
    void emit_optional_rex_32(fuku_register reg, fuku_register rm_reg);
    void emit_optional_rex_32(fuku_register reg, const fuku_operand& op);
    void emit_optional_rex_32(fuku_register rm_reg);
    void emit_optional_rex_32(const fuku_operand& op);


    void emit_rex(fuku_operand_size size);
    void emit_rex(const fuku_operand& rm_reg, fuku_operand_size size);
    void emit_rex(fuku_register reg, fuku_operand_size size);
    void emit_rex(fuku_register reg, fuku_register rm_reg, fuku_operand_size size);
    void emit_rex(fuku_register reg, const fuku_operand& rm_reg, fuku_operand_size size);

    void emit_modrm(fuku_register reg, fuku_register rm_reg);
    void emit_modrm(int code, fuku_register rm_reg);

    void emit_operand(fuku_register_index reg, const fuku_operand& adr);

public:
    fuku_asm_x64();
    ~fuku_asm_x64();

    uint8_t get_displacment_offset();
    uint8_t get_immediate_offset();

    bool is_used_short_eax();
    bool is_used_short_disp();
    bool is_used_short_imm();
public:
    fuku_instruction nop(int n);
};


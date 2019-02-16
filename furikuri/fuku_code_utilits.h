#pragma once

bool has_inst_free_register(fuku_instruction& inst, x86_reg reg);
bool has_inst_free_register(fuku_instruction& inst, fuku_register_enum reg);
bool has_inst_free_eflags(uint64_t inst_eflags, uint64_t flags); //used only with MODIFY prefix

//uint64_t convert_fuku_reg_to_flag_reg(fuku_register_enum reg);
fuku_register_enum  convert_flag_reg_to_fuku_reg(uint64_t reg);
uint64_t convert_fuku_reg_to_flag_reg(fuku_register_enum reg);
uint64_t convert_fuku_reg_to_complex_flag_reg(fuku_register reg, uint8_t size = 0);
fuku_register_enum get_random_reg(uint32_t reg_size, bool x86_only, uint64_t exclude_reg = 0);
fuku_register_enum get_random_free_flag_reg(uint64_t reg_flags, uint32_t reg_size, bool x86_only, uint64_t exclude_reg = FUKU_REG_NONE);
fuku_register_enum get_random_free_flag_reg(fuku_instruction& inst, uint32_t reg_size, bool x86_only, uint64_t exclude_reg = FUKU_REG_NONE);
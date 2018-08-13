#pragma once

void vm_operand_create(vm_context& context) {
    context.operands.push_back(0);
}

void vm_operand_set_base_link_reg(vm_context& context) {
    vm_operand_set_base_link_reg_code * link_reg = (vm_operand_set_base_link_reg_code *)&context.vm_code[0];

    context.operands[context.operands.size() - 1] = (uint32_t)&context.real_context.d_regs[7 - link_reg->reg];

    context.vm_code += sizeof(vm_operand_set_base_link_reg_code);
}

void vm_operand_set_base(vm_context& context) {
    vm_operand_set_base_code * base = (vm_operand_set_base_code *)&context.vm_code[0];

    context.operands[context.operands.size() - 1] += context.real_context.d_regs[7 - base->reg];

    context.vm_code += sizeof(vm_operand_set_base_code);
}

void vm_operand_set_index_scale(vm_context& context) {
    vm_operand_set_index_scale_code * index_scale = (vm_operand_set_index_scale_code *)&context.vm_code[0];

    context.operands[context.operands.size() - 1] += context.real_context.d_regs[7 - index_scale->reg] * index_scale->scale;

    context.vm_code += sizeof(vm_operand_set_index_scale_code);
}

void vm_operand_set_disp(vm_context& context) {
    vm_operand_set_disp_code * disp = (vm_operand_set_disp_code *)&context.vm_code[0];

    context.operands[context.operands.size() - 1] += disp->disp;

    context.vm_code += sizeof(vm_operand_set_disp_code);
}
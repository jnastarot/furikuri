#pragma once

void vm_clc(vm_context& context) {
    context.real_context.flags._cf = 0;
}

void vm_cmc(vm_context& context) {
    context.real_context.flags._cf = !context.real_context.flags._cf;
}

void vm_stc(vm_context& context) {
    context.real_context.flags._cf = 1;
}

void vm_cld(vm_context& context) {
    context.real_context.flags._df = 0;
}

void vm_std(vm_context& context) {
    context.real_context.flags._df = 1;
}
#pragma once


//graph
void fukutate_86_jcc(mutation_context& ctx);
void fukutate_86_jmp(mutation_context& ctx);
void fukutate_86_call(mutation_context& ctx);
void fukutate_86_ret(mutation_context& ctx);

//stack
void fukutate_86_push(mutation_context& ctx);
void fukutate_86_pop(mutation_context& ctx);

//data transfer
void fukutate_86_mov(mutation_context& ctx);
void fukutate_86_xchg(mutation_context& ctx);
void fukutate_86_lea(mutation_context& ctx);

//aritch
void fukutate_86_add(mutation_context& ctx);
void fukutate_86_or(mutation_context& ctx);
void fukutate_86_adc(mutation_context& ctx);
void fukutate_86_sbb(mutation_context& ctx);
void fukutate_86_and(mutation_context& ctx);
void fukutate_86_sub(mutation_context& ctx);
void fukutate_86_xor(mutation_context& ctx);
void fukutate_86_cmp(mutation_context& ctx);
void fukutate_86_inc(mutation_context& ctx);
void fukutate_86_dec(mutation_context& ctx);
void fukutate_86_test(mutation_context& ctx);
void fukutate_86_not(mutation_context& ctx);
void fukutate_86_neg(mutation_context& ctx);
void fukutate_86_mul(mutation_context& ctx);
void fukutate_86_imul(mutation_context& ctx);
void fukutate_86_div(mutation_context& ctx);
void fukutate_86_idiv(mutation_context& ctx);

//shift
void fukutate_86_rol(mutation_context& ctx);
void fukutate_86_ror(mutation_context& ctx);
void fukutate_86_rcl(mutation_context& ctx);
void fukutate_86_rcr(mutation_context& ctx);
void fukutate_86_shl(mutation_context& ctx);
void fukutate_86_shr(mutation_context& ctx);
void fukutate_86_sar(mutation_context& ctx);

//bittest
void fukutate_86_bt(mutation_context& ctx);
void fukutate_86_bts(mutation_context& ctx);
void fukutate_86_btr(mutation_context& ctx);
void fukutate_86_btc(mutation_context& ctx);
void fukutate_86_bsf(mutation_context& ctx);
void fukutate_86_bsr(mutation_context& ctx);




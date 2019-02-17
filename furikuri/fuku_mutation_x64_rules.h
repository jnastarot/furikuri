#pragma once


//graph
void fukutate_64_jcc(mutation_context & ctx);
void fukutate_64_jmp(mutation_context & ctx);
void fukutate_64_call(mutation_context & ctx);
void fukutate_64_ret(mutation_context & ctx);

//stack
void fukutate_64_push(mutation_context & ctx);
void fukutate_64_pop(mutation_context & ctx);

//data transfer
void fukutate_64_mov(mutation_context & ctx);
void fukutate_64_xchg(mutation_context & ctx);
void fukutate_64_lea(mutation_context & ctx);

//aritch
void fukutate_64_add(mutation_context & ctx);
void fukutate_64_or(mutation_context & ctx);
void fukutate_64_adc(mutation_context & ctx);
void fukutate_64_sbb(mutation_context & ctx);
void fukutate_64_and(mutation_context & ctx);
void fukutate_64_sub(mutation_context & ctx);
void fukutate_64_xor(mutation_context & ctx);
void fukutate_64_cmp(mutation_context & ctx);
void fukutate_64_inc(mutation_context & ctx);
void fukutate_64_dec(mutation_context & ctx);
void fukutate_64_test(mutation_context & ctx);
void fukutate_64_not(mutation_context & ctx);
void fukutate_64_neg(mutation_context & ctx);
void fukutate_64_mul(mutation_context & ctx);
void fukutate_64_imul(mutation_context & ctx);
void fukutate_64_div(mutation_context & ctx);
void fukutate_64_idiv(mutation_context & ctx);

//shift
void fukutate_64_rol(mutation_context & ctx);
void fukutate_64_ror(mutation_context & ctx);
void fukutate_64_rcl(mutation_context & ctx);
void fukutate_64_rcr(mutation_context & ctx);
void fukutate_64_shl(mutation_context & ctx);
void fukutate_64_shr(mutation_context & ctx);
void fukutate_64_sar(mutation_context & ctx);

//bittest
void fukutate_64_bt(mutation_context & ctx);
void fukutate_64_bts(mutation_context & ctx);
void fukutate_64_btr(mutation_context & ctx);
void fukutate_64_btc(mutation_context & ctx);
void fukutate_64_bsf(mutation_context & ctx);
void fukutate_64_bsr(mutation_context & ctx);

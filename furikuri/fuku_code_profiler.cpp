#include "stdafx.h"
#include "fuku_code_profiler.h"


fuku_code_profiler::fuku_code_profiler() {}
fuku_code_profiler::~fuku_code_profiler() {}

void fuku_code_profiler::profile_code(fuku_code_holder& code) {

    for (auto line_iter = code.get_lines().begin(); line_iter != code.get_lines().end(); line_iter++) {

        uint64_t unused_flags = 0;


        if (!GET_BITES(line_iter->get_eflags(), X86_EFLAGS_GROUP_TEST)) {

            auto next_line_iter = line_iter; next_line_iter++;

            for (; next_line_iter != code.get_lines().end(); next_line_iter++) {

                if (unused_flags == (X86_EFLAGS_GROUP_MODIFY | X86_EFLAGS_GROUP_SET | X86_EFLAGS_GROUP_RESET | X86_EFLAGS_GROUP_UNDEFINED)
                    || GET_BITES(next_line_iter->get_eflags(), X86_EFLAGS_GROUP_TEST) || next_line_iter->get_label_idx() != -1) {

                    break;
                }

                uint16_t id = next_line_iter->get_id();

                switch (id) {

                case X86_INS_JMP: case X86_INS_RET: case X86_INS_CALL: {
                    goto routine_exit;
                }

                default: {
                    break;
                }
                }

                unused_flags |= GET_BITES(next_line_iter->get_eflags(), X86_EFLAGS_GROUP_MODIFY | X86_EFLAGS_GROUP_SET | X86_EFLAGS_GROUP_RESET | X86_EFLAGS_GROUP_UNDEFINED);
            }
        }
    routine_exit:;

        line_iter->set_custom_flags(unused_flags);
    }
}
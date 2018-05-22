#pragma once
#include "..\distorm_lib\include\distorm.h"
#include "..\distorm_lib\include\mnemonics.h"

class fuku_obfuscator;
class fuku_instruction;
class fuku_mutation;

struct ob_fuku_sensitivity {
    unsigned int complexity;        //number of passes for single line
    unsigned int number_of_passes;  //number of passes for full code
    float junk_chance;   //0.f - 100.f chance of adding junk
    float block_chance;  //0.f - 100.f chance of generation new code graph
    float mutate_chance; //0.f - 100.f chance of mutation line
};

struct fuku_code_list {
    std::vector<uint32_t> func_starts;
    std::vector<shibari_module_symbol_info> code_placement;
};

#include "fuku_instruction.h"
#include "fuku_mutation.h"
#include "fuku_obfuscator.h"
#include "fuku_asm.h"

#include "fuku_graph_spider.h"
#include "fuku_protector.h"

class furikuri {

public:
    furikuri::furikuri();
    furikuri::~furikuri();
};


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

#include "fuku_debug_info.h"

#include "fuku_module_decoder.h"
#include "fuku_protector.h"

class furikuri {
    std::vector<shibari_module*> extended_modules;
    shibari_module* main_module;

public:
    furikuri::furikuri();
    furikuri::~furikuri();

    bool furikuri::fuku_protect(const ob_fuku_sensitivity& settings, std::vector<uint8_t>& out_image, fuku_code_list * _code_list = 0);
public:
    bool furikuri::set_main_module(shibari_module* module,std::string module_path = "");
    bool furikuri::add_extended_module(shibari_module* module, std::string module_path = "");

public:
    std::vector<shibari_module*>& furikuri::get_extended_modules();
    shibari_module* furikuri::get_main_module();
};


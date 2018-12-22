#pragma once

#include "..\capstone\include\capstone\capstone.h"

#define X86_EFLAGS_GROUP_TEST (X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_ZF | X86_EFLAGS_TEST_PF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_DF | X86_EFLAGS_TEST_AF)
#define X86_EFLAGS_GROUP_MODIFY (X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF | X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_DF | X86_EFLAGS_MODIFY_AF)
#define X86_EFLAGS_GROUP_SET (X86_EFLAGS_SET_CF | X86_EFLAGS_SET_DF | X86_EFLAGS_SET_OF | X86_EFLAGS_SET_SF | X86_EFLAGS_SET_ZF | X86_EFLAGS_SET_AF | X86_EFLAGS_SET_PF)
#define X86_EFLAGS_GROUP_RESET (X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_CF | X86_EFLAGS_RESET_DF | X86_EFLAGS_RESET_SF | X86_EFLAGS_RESET_AF | X86_EFLAGS_RESET_ZF)
#define X86_EFLAGS_GROUP_UNDEFINED (X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF | X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_AF | X86_EFLAGS_UNDEFINED_CF)

enum fuku_code_type {
    fuku_code_obfuscation,
    fuku_code_virtualization,
};

enum fuku_arch {
    fuku_arch_unknown,
    fuku_arch_x32,
    fuku_arch_x64
};

class fuku_code_analyzer;
class fuku_obfuscator;
class fuku_instruction;
class fuku_mutation;
class fuku_virtualizer;

struct fuku_ob_settings {
    unsigned int complexity;        //number of passes for single line
    unsigned int number_of_passes;  //number of passes for full code
    float junk_chance;   //0.f - 100.f chance of adding junk
    float block_chance;  //0.f - 100.f chance of generation new code graph
    float mutate_chance; //0.f - 100.f chance of mutation line

    bool fuku_ob_settings::operator==(const fuku_ob_settings& set);
    bool is_null() const;
};

struct fuku_vm_settings {
    fuku_ob_settings ob_settings;

    shibari_module* vm_holder_module;//vm holder
    uint32_t  vm_entry_rva;          //vm offset

    fuku_virtualizer * virtualizer;
};

struct fuku_protected_region {
    uint32_t region_rva;
    uint32_t region_size;
};

struct fuku_code_list {
    fuku_code_type type;

    std::vector<fuku_protected_region> functions;
   
    fuku_ob_settings settings;
    shibari_module*  target_module;

    shibari_module*  vm_holder_module;
    uint32_t         vm_entry_rva;
    fuku_virtualizer * virtualizer;

    fuku_code_list& fuku_code_list::operator=(const fuku_code_list& set);
};

#include "fuku_instruction.h"
#include "fuku_vm_instruction.h"

#include "fuku_asm.h"
#include "fuku_code_holder.h"
#include "fuku_code_analyzer.h"
#include "fuku_obfuscator.h"
#include "fuku_virtualizer_imp.h"
#include "fuku_debug_info.h"
#include "fuku_protector.h"

class furikuri {
    std::vector<shibari_module*> extended_modules;
    shibari_module* main_module;

    std::vector<fuku_code_list> code_lists;
public:
    furikuri::furikuri();
    furikuri::~furikuri();

    bool furikuri::fuku_protect(std::vector<uint8_t>& out_image);
public:
    bool furikuri::set_main_module(shibari_module* module,std::string module_path = "");
    bool furikuri::add_extended_module(shibari_module* module, std::string module_path = "");

    bool furikuri::add_ob_code_list(fuku_protected_region region, shibari_module* target_module,const fuku_ob_settings& settings);
    bool furikuri::add_vm_code_list(fuku_protected_region region, shibari_module* target_module,const fuku_vm_settings& settings);

    void furikuri::clear_code_lists();
    void furikuri::clear_extended_modules(); //delete only from pointer table without destruction classes
public:
    const std::vector<fuku_code_list> & furikuri::get_code_lists() const;
    std::vector<shibari_module*>& furikuri::get_extended_modules();
    shibari_module* furikuri::get_main_module();
};


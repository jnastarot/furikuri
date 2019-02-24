#pragma once

#include "..\capstone\include\capstone\capstone.h"
#include "..\fukutasm\fukutasm\fukutasm.h"

using namespace fukutasm;

class fuku_code_analyzer;
class fuku_code_profiler;
class fuku_mutation;
class fuku_virtualizer;
class fuku_obfuscator;



struct mutation_context {
    fuku_assambler *f_asm;
    fuku_code_holder* code_holder;

    cs_insn *instruction;
    linestorage::iterator first_junk_line_iter;
    linestorage::iterator first_line_iter;
    linestorage::iterator current_line_iter;
    linestorage::iterator next_line_iter;

    bool has_unstable_stack;
    bool is_first_line_begin;
    bool is_next_line_end;
    bool was_mutated;
    bool was_junked;

    size_t   label_idx;
    uint64_t source_virtual_address;

    uint32_t instruction_flags;
    uint64_t eflags_changes;
    uint64_t regs_changes;

    bool swap_junk_label;
    size_t junk_label_idx;
};

#include "fuku_settings_obfuscation.h"
#include "fuku_settings_virtualization.h"

#include "fuku_code_utilits.h"
#include "fuku_code_profiler.h"
#include "fuku_code_analyzer.h"
#include "fuku_obfuscator.h"
#include "fuku_virtualizer_imp.h"
#include "fuku_protect_mgr.h"

enum fuku_code_raw_list_type {
    CODE_RAW_LIST_TYPE_NONE,
    CODE_RAW_LIST_TYPE_OBFUSCATION,
    CODE_RAW_LIST_TYPE_VIRTUALIZATION,
};

class fuku_code_raw_list {
    fuku_code_raw_list_type type;

    std::vector<fuku_protected_region> functions;

    fuku_settings_obfuscation settings;
    shibari_module*  target_module;

    shibari_module*  vm_holder_module;
    uint32_t vm_entry_rva;
    fuku_virtualizer * virtualizer;

public:
    fuku_code_raw_list();
    fuku_code_raw_list(fuku_code_raw_list_type type, const std::vector<fuku_protected_region>& regions,
        const fuku_settings_obfuscation& settings, shibari_module*  target_module,
        shibari_module*  vm_holder_module, uint32_t vm_entry_rva, fuku_virtualizer * virtualizer);

    fuku_code_raw_list(const fuku_code_raw_list& list);
    ~fuku_code_raw_list();

    fuku_code_raw_list& operator=(const fuku_code_raw_list& list);
public:
    void set_type(fuku_code_raw_list_type type);
    void set_functions(const std::vector<fuku_protected_region>& functions);
    void set_settings(const fuku_settings_obfuscation& settings);
    void set_target_module(shibari_module* _module);
    void set_vm_holder_module(shibari_module* _module);
    void set_vm_entry_rva(uint32_t entry_rva);
    void set_virtualizer(fuku_virtualizer * virt);
   
public:
    std::vector<fuku_protected_region>& get_functions();
    fuku_settings_obfuscation& get_settings();
    shibari_module*  get_target_module();
    shibari_module*  get_vm_holder_module();
    fuku_virtualizer * get_virtualizer();

public:
    const fuku_code_raw_list_type get_type() const;
    const std::vector<fuku_protected_region>& get_functions() const;
    const fuku_settings_obfuscation& get_settings() const;
    const shibari_module*  get_target_module() const;
    const shibari_module*  get_vm_holder_module() const;
    const uint32_t         get_vm_entry_rva() const;
    const fuku_virtualizer * get_virtualizer() const;

};

class furikuri {
    std::vector<shibari_module*> extended_modules;
    shibari_module* main_module;

    std::vector<fuku_code_raw_list> code_raw_lists;
public:
    furikuri::furikuri();
    furikuri::~furikuri();

    bool furikuri::fuku_protect(std::vector<uint8_t>& out_image);
public:
    bool furikuri::set_main_module(shibari_module* module,std::string module_path = "");
    bool furikuri::add_extended_module(shibari_module* module, std::string module_path = "");

    bool furikuri::add_ob_code_list(fuku_protected_region region, shibari_module* target_module, fuku_settings_obfuscation& settings);
    bool furikuri::add_vm_code_list(fuku_protected_region region, shibari_module* target_module, fuku_settings_virtualization& settings);

    void furikuri::clear_code_lists();
    void furikuri::clear_extended_modules(); //delete only from pointer table without destruction classes
public:
    const std::vector<fuku_code_raw_list> & furikuri::get_code_raw_lists() const;
    std::vector<shibari_module*>& furikuri::get_extended_modules();
    shibari_module* furikuri::get_main_module();
};


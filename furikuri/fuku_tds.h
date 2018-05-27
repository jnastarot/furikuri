#pragma once

struct fuku_tds_section {
    uint32_t offset;
    uint32_t size;
    uint16_t index;
    uint16_t type;
};

enum fuku_tds_result {
    tds_result_ok,
    tds_result_error
};


struct tds_header {
    uint32_t magic;
    uint32_t subsection_offset;
};

struct tds_subsection_dir_item {
    uint16_t type; // SubSectTypes
    uint16_t index;
    uint32_t offset;
    uint32_t size;
};

struct tds_subsection_dir {
    uint32_t unknown1;
    uint32_t num;
    uint32_t unknown2;
    uint32_t unknown3;
    tds_subsection_dir_item items[1];
};

struct tds_module_segment {
    uint16_t index;
    uint16_t flags;
    uint32_t start;
    uint32_t end;
};

struct tds_module_subsection {
    uint16_t overlay_num; // ?
    uint16_t lib_index; // ?
    uint16_t segments_count;
    uint16_t unknown1;
    uint16_t name;
    uint16_t time; // ?
    uint32_t unknown2;
    uint32_t unknown3;
    uint32_t unknown4;
    uint32_t unknown5;
    tds_module_segment segments[1];
};


#pragma pack(2)
struct tds_scompiler {
    uint32_t machine_and_compiler_flags;
    uint8_t  compiler_name_len;
    char     compiler_name[1];
};

struct tds_sregister {
    uint32_t type;
    uint16_t _register;
    uint32_t name;
    uint32_t browser_offset;
};

struct tds_sconst {
    uint32_t type;
    uint32_t name;
    uint32_t browser_offset;
    char value[1];
};

struct tds_sudt {
    uint32_t type;
    uint32_t name;
    uint32_t browser_offset;
};

struct tds_ssearch {
    uint32_t offset;
    uint16_t segment;
    uint16_t code_symbols;
    uint16_t data_symbols;
    uint32_t first_data;
    uint16_t unknown1;
};

struct tds_sgproc_ref {
    uint32_t unknown1;
    uint32_t type;
    uint32_t name;
    uint32_t browser_offset;
    uint32_t offset;
    uint16_t segment;
    uint32_t unknown2;
};

struct tds_sgdata_ref {
    uint32_t unknown1;
    uint32_t type;
    uint32_t name;
    uint32_t browser_offset;
    uint32_t offset;
    uint16_t segment;
};

struct tds_spconstant {
    uint32_t type;
    uint16_t _property;
    uint32_t name;
    uint32_t browser_offset;
    char     value[1];
};

struct tds_sbprel32 {
    uint32_t ebp_offset;
    uint16_t type;
    uint16_t unknown1;
    uint16_t name;
    uint16_t unknown2;
    uint16_t unknown3;
    uint16_t unknown4;
};

struct tds_sdata32 {
    uint32_t offset;
    uint16_t segment;
    uint16_t flags;
    uint32_t type;
    uint32_t name;
    uint32_t browser_offset;
};

struct tds_sproc32 {
    uint32_t parent;
    uint32_t end;
    uint32_t next;
    uint32_t size1;
    uint32_t unknown1;
    uint32_t size;
    uint32_t start;
    uint16_t segment;
    uint16_t unknown2;
    uint16_t type;
    uint16_t unknown3;
    uint16_t name;
    uint32_t unknown4;
    uint16_t unknown5;
    // for global only
    uint8_t linker_name_len;
    char linker_name[1];
};

struct tds_sblock32 {
    uint32_t parent;
    uint32_t end;
    uint32_t size;
    uint32_t start;
    uint16_t segment;
    uint32_t name;
};

struct tds_swith32 {
    uint32_t parent;
    uint32_t code_length;
    uint32_t procedure_offset;
    uint16_t segment;
    uint16_t flags;
    uint32_t type;
    uint32_t name;
    uint32_t var_offset;
};

struct tds_sentry32 {
    uint32_t offset;
    uint16_t segment;
};

struct tds_sopt_var32 {
    uint16_t num;

    struct {
        uint32_t start;
        uint32_t size;
        uint16_t _register;
    } items[1];
};

struct tds_sproc_ret32 {
    uint32_t offset;
    uint16_t lenght;
};



struct tds_ssave_regs32 {
    uint16_t mask; // 7 = EBX EDI ESI; 1 = EBX; 6 = EDI, ESI; 5 = EBX ESI
    uint32_t ebp_offset;
};


struct tds_modifier {
    uint16_t mod;
    uint32_t type;
};

struct tds_pointer {
    uint16_t ptr_type_mod;
    uint32_t points_to;
    // valid only for member or method pointers
    uint16_t format;
    uint32_t _class;
};

// T_ARRAY
struct tds_array {
    uint32_t element_type;
    uint32_t indexer_type;
    uint32_t name;
    // Next goes variable length ArraySize and NumElements fields
};

// T_CLASS
// T_STRUCT
struct tds_class {
    uint16_t num_members; // number of members
    uint32_t field_index; // reference to FIELDLIST description of fields
    uint16_t flags;
    uint32_t containing_class;
    uint32_t derivation_list;
    uint32_t vtable;
    uint32_t name;
    // next goes variable length field Size (size of instance)
};

struct tds_union {
    uint16_t num_members;
    uint32_t field_index;
    uint16_t flags;
    uint32_t containing_class;
    uint32_t name;
    // next goes variable length field Size (size of instance)
};

struct tds_enum {
    uint16_t count;
    uint32_t type;
    uint32_t fields;
    uint32_t _class;
    uint32_t name;
};

struct tds_procedure {
    uint32_t type;
    uint16_t call_type;
    uint16_t params;
    uint32_t arg_list;
};

// T_MFUNCTION = 0x9, /*[Type 32][Class 32][This 32][CallType 16][Params 16][Args 32][Adjust 32]*/
struct tds_member_function {
    uint32_t type;
    uint32_t _class;
    uint32_t _this;
    uint16_t call_type;
    uint16_t params;
    uint32_t arg_list;
    uint32_t adjust;
};


struct tds_bclass {
    uint32_t index;
    uint16_t access;
    uint16_t offset;
};

struct tds_vbclass {
    uint32_t base;
    uint32_t virtual_base;
    uint16_t access;
    uint16_t virt_base_ptr_offset;
    uint16_t unknown1; // 0x8001
    uint16_t virt_base_index;
};

struct tds_enumerate {
    uint16_t attribs;
    uint32_t name;
    uint32_t browser_offset;
};

struct tds_member {
    uint32_t type;
    uint16_t access;
    uint32_t name;
    uint32_t browser_offset;
    uint16_t offset;
};

struct tds_static_member {
    uint32_t type;
    uint16_t access;
    uint32_t name;
    uint32_t browser_offset;
};

struct tds_method {
    uint16_t count;
    uint32_t index;
    uint32_t name;
};

struct tds_nest_type {
    uint32_t index;
    uint32_t name;
    uint32_t browser_offset;
};

struct tds_global_sym_header {
    uint16_t sym_hash;
    uint16_t addr_hash;
    uint32_t cb_symbols;
    uint32_t cb_sym_hash;
    uint32_t cb_addr_hash;
    uint32_t c_udts;
    uint32_t c_others;
    uint32_t total;
    uint32_t c_name_spaces;
};

// T_METHODLIST 0x7
struct tds_method_lstitem {
    uint16_t access_storage;
    uint32_t type;
    uint32_t browser_offset;
    uint32_t vtab_offset; // only for virtual and introducing virtual
};

struct tds_escaped_field {
    const char * ptr;
    size_t size;
};


class fuku_tds {
    std::vector<std::string> names_pool;
    std::vector<uint8_t> tds_data;

    fuku_tds_result result;

    std::string fuku_tds::get_name_by_id(uint32_t id) const;
    uint32_t fuku_tds::get_id_by_name(const std::string &name) const;

    void fuku_tds::load_names(uint8_t * names_ptr);

    void fuku_tds::PrintSymbolSearch(const tds_ssearch * ss);
    void fuku_tds::PrintGlobalProcRef(const tds_sgproc_ref * p);
    void fuku_tds::PrintGlobalDataRef(const tds_sgdata_ref * d);
    void fuku_tds::PrintCompiler(const tds_scompiler * comp);
    void fuku_tds::PrintSConst(const tds_sconst * c);
    void fuku_tds::PrintSUdt(const tds_sudt * u);
    void fuku_tds::PrintSUsing(const uint8_t * u);
    void fuku_tds::PrintSPConstant(const tds_spconstant * c);
    void fuku_tds::PrintSBPRel32(const tds_sbprel32 * bp);
    void fuku_tds::PrintSData32(const tds_sdata32 * dat);
    void fuku_tds::PrintSProc32(const tds_sproc32 * proc, size_t size);
    void fuku_tds::PrintSBlock32(const tds_sblock32 * b);
    void fuku_tds::PrintSWith32(const tds_swith32 * w);
    void fuku_tds::PrintSEntry32(const tds_sentry32 * e);
    void fuku_tds::ParseSymbols(const uint8_t * start, const uint8_t * end);
    void fuku_tds::ParseAlignSym(uint8_t * start, uint8_t * end, int moduleIndex);
    void fuku_tds::ParseGlobalSym(uint8_t * start);
    void fuku_tds::ParseSrcModule(uint8_t * start, uint8_t * end);
    void fuku_tds::ParseArray(const uint8_t * start);
    void fuku_tds::ParseStruct(const uint8_t * start, unsigned type);
    void fuku_tds::ParseVirtTblShape(const uint8_t * start);
    void fuku_tds::ParseArgList(const uint8_t * start);
    void fuku_tds::ParseFieldList(const uint8_t * start, const uint8_t * end);
    void fuku_tds::ParseMethodList(const uint8_t * start, const uint8_t * end);
    void fuku_tds::ParseGlobalTypes(uint8_t * start);

public:
    fuku_tds::fuku_tds();
    fuku_tds::~fuku_tds();

    fuku_tds_result fuku_tds::load_from_file(const std::string& tds_path);
    fuku_tds_result fuku_tds::load_from_data(const std::vector<uint8_t>& tds_data);
public:
    
};


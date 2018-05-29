#include "stdafx.h"
#include "fuku_tds.h"

/*
   rewrited code from
 http://denisenkomik.narod.ru/main.cpp
*/

#define TD_CLASS_MASK 0xFFFFFE00
#define TD_TYPE_MASK  (~TD_CLASS_MASK)
#define TD_SUBTYPE_CLASS_MASK  (0x1F0 & TD_TYPE_MASK)
#define TD_SUBTYPE_MASK  (~(TD_CLASS_MASK | TD_SUBTYPE_CLASS_MASK))

// type def classes
#define TDC_ROOT  0x000
#define TDC_LIST  0x200
#define TDC_LIST_ITEM  0x400
// type def sub types
#define TDST_GENERIC  0x000
#define TDST_PASCAL   0x030
//const unsigned int TDST_UNKNOWN = 0x0E0;
#define TYPE_TYPE_MASK 0xf0
#define TYPE_SIZE_MASK 0x0f
#define TYPE_POINTER_MASK 0xF00

#define FT_CALL_TYPE_MASK  0x0F
#define FT_VARARGS 0x40
#define FT_FAST_THIS  0x80
#define FT_UNKFLAG1  0x100
#define FT_UNKFLAG2  0x200
#define FT_UNKFLAG3  0x400
#define FT_UNKFLAG4  0x800
#define FT_UNKFLAG5  0x1000
#define FT_UNKFLAG6  0x2000
#define FT_UNKFLAG7  0x4000
#define FT_UNKFLAG8  0x8000
#define FT_VALID_FLAGS (FT_UNKFLAG1 | FT_VARARGS | FT_UNKFLAG2 | FT_UNKFLAG3 | FT_UNKFLAG4 | FT_UNKFLAG5 | FT_UNKFLAG6 | FT_UNKFLAG7 | FT_UNKFLAG8)

#define PTR_TYPE_MASK 0x1F
#define PTR_MODE_MASK 0xE0

// pointer modifier flags
#define PMF_16_32       0x0100
#define PMF_VOLATILE    0x0200
#define PMF_CONST       0x0400
#define PMF_VALID_FLAGS  (PMF_16_32 | PMF_VOLATILE | PMF_CONST)

#define PTR_TYPE_FIELD(x) ((x) & PTR_TYPE_MASK)
#define PTR_MODE_FIELD(x) (((x) & PTR_MODE_MASK) >> 5)

#define CF_PACKED               0x1
#define CF_CONSTRUCTORS         0x2
#define CF_OVERLOADED_OPERATORS 0x4
#define CF_IS_NESTED            0x8
#define CF_NESTED_CLASSES       0x10
#define CF_OVERLOAD_ASSIGNMENT  0x20
#define CF_CASTING_METHODS      0x40
#define CF_FORWARD_REFERENCE    0x80
#define CF_DESTRUCTORS          0x100
#define CF_VALID_FLAGS  (CF_PACKED | CF_CONSTRUCTORS | CF_OVERLOADED_OPERATORS | \
CF_IS_NESTED | CF_NESTED_CLASSES | CF_OVERLOAD_ASSIGNMENT | CF_CASTING_METHODS | \
CF_FORWARD_REFERENCE | CF_DESTRUCTORS)

#define METHOD_ACCESS_FIELD(x) ((x) & 3)
#define METHOD_STORAGE_FIELD(x) (((x) & 0x001C) >> 2)
#define METHOD_FLAGS_FIELD(x) ((x) & 0xFFE0)

#define MDF_DEFAULT1            0x0020
#define MDF_OPERATOR_OVERLOAD   0x0100
#define MDF_CONVERSION_OPERATOR 0x0200
#define MDF_CONSTRUCTOR         0x0400
#define MDF_DESTRUCTOR          0x0800
#define MDF_DEFAULT2            0x1000
#define MDF_VALID_FLAGS (MDF_DEFAULT1 | MDF_OPERATOR_OVERLOAD | MDF_CONVERSION_OPERATOR | MDF_CONSTRUCTOR | MDF_DESTRUCTOR | MDF_DEFAULT2)

// Save Regs Masks
#define S_EBX 1
#define S_EDI 2
#define S_ESI 4


enum tds_subsection_header{

    sst_module      = 0x120,
    sst_alignsym    = 0x125,
    sst_srcmodule   = 0x127,
    sst_globalsym   = 0x129,
    sst_globaltypes = 0x12b,
    sst_names       = 0x130,
};

enum tds_symbol_align_type {

    S_COMPILE = 0x01,
    S_REGISTER = 0x02,
    S_CONST = 0x03,
    S_UDT = 0x04,
    S_SSEARCH = 0x05,
    S_END = 0x06,
    S_SKIP = 0x07,
    S_CVRESERVE = 0x08,
    S_OBJNAME = 0x09,
    S_ENDARG = 0x0A,
    S_COBOLUDT = 0x0B,
    S_MANYREG = 0x0C,
    S_RETURN = 0x0D,
    S_ENTRYTHIS = 0x0E,
    /*0xF-0x1F unused */
    S_GPROCREF = 0x20, /* [Address 32][Type 32][Name 32][Browser offset 32][Offset 32][Segment 16] */
    S_GDATAREF = 0x21, /* [Address 32][Type 32][Name 32][Browser offset 32][Offset 32][Segment 16] */
    S_EDATA = 0x22, /* [Type 32][Name 32][unk 16][EI 16][Browser offset 32]*/
    S_EPROC = 0x23, /* [Type 32][Name 32][unk 16][EI 16][Browser offset 32]*/
    S_USES = 0x24,
    S_NAMESPACE = 0x25,
    S_USING = 0x26,
    S_PCONSTANT = 0x27,
};

enum tds_symbol_align_sized_type {

    S_BPREL = 0x0,
    S_LDATA = 0x1,
    S_GDATA = 0x2,
    S_PUB = 0x3, /* [Offset 32][Segment 16][Flags 16][Type 32][Name 32][Browser offset 32]*/
    S_LPROC = 0x4,
    S_GPROC = 0x5,
    S_THUNK = 0x6, /*[Parent 32][End 32][Next 32][Offset 32][Segment 16][Length 16][Name 32][Ordinal 8][Some flags 8]*/
    S_BLOCK = 0x7,
    S_WITH = 0x8,
    S_LABEL = 0x9, /*[Offset 32][Segment 16][Some byte 8][Name 32]*/
                   /*0x unused*/
                   S_VFTPATH = 0xB,
                   S_VFTREGREL = 0xC,
                   S_LTHREAD = 0xD,
                   S_GTHREAD = 0xE,
                   /*0xF unused*/
                   S_ENTRY = 0x10, /*[Offset 32][Segment 16]*/
                   S_OPTVAR = 0x11,
                   S_PROCRET = 0x12,
                   S_SAVREGS = 0x13,
                   /*0x14-2F*/
                   S_SLINK = 0x30,
};




enum tds_typdef_root_type {

    T_STARTYP = 0x0,
    T_MODIFIER = 0x1,
    T_POINTER = 0x2,
    T_ARRAY = 0x3, /*[Type 32][Indexer type 32][Name 32][Size 16][Num 16]*/
    T_CLASS = 0x4,
    T_STRUCT = 0x5,
    T_UNION = 0x6,
    T_ENUM = 0x7,
    T_PROCEDURE = 0x8, /*[Type 32][CallType 16][Params 16][Args 32]*/
    T_MFUNCTION = 0x9, /*[Type 32][Class 32][This 32][CallType 16][Params 16][Args 32][Adjust 32]*/
    T_VTSHAPE = 0xA, /*[NumEntries 16][Entry1 4][Entry2 4]...*/
                     //COBOL0 = 0xB,
                     //COBOL1 = 0xC,
                     //BARRAY = 0xD,
                     T_LABEL = 0xE,
                     //NULL = 0xF,
                     //NOTTRAN = 0x10,
                     //DIMARRAY = 0x11,
                     //VFTPATH = 0x12,
                     // 13-2F  unused
                     //3A-EE tdump reports: Not yet handled
                     //T_UNKNOWN3 = 0xEF, // tdump reports: Unknown type. Could be unresolved external type reference.
};

enum tds_typdef_pas_type {

    T_SET = 0x0,
    T_SUBRANGE = 0x1,
    T_UNKNOWN = 0x2,
    T_PSTRING = 0x3,
    T_CLOSURE = 0x4,
    T_PROPERTY = 0x5,
    T_LSTRING = 0x6,
    T_VARIANT = 0x7,
    T_CLASSREF = 0x8,
    T_UNKNOWN2 = 0x9,
};

enum tds_typdef_listtype {

    //T_SKIP = 0x0,
    T_ARGLIST = 0x1,
    T_DEFARG = 0x2,
    T_LIST = 0x3,
    T_FIELDLIST = 0x4,
    T_DERIVED = 0x5,
    T_BITFIELD = 0x6,
    T_METHODLIST = 0x7, // [[Access/prop 16][Type 32][Browser offset 32]]... prop: 0x4 - virtual, 0x8 - static, 0xc - friend, 0x10 - introducing virtual
    T_DIMCONU = 0x8,
    T_DIMCONLU = 0x9,
    T_DIMVARU = 0xA,
    T_DIMVARLU = 0xB,
    T_REFSYM = 0xC,
};

enum tds_typdef_lstitemtype {

    T_BCLASS = 0x0,
    T_VBCLASS = 0x1,
    T_IVBCLASS = 0x2,
    T_ENUMERATE = 0x3,
    T_INDEX = 0x5,
    T_MEMBER = 0x6,
    T_STMEMBER = 0x7,
    T_METHOD = 0x8,
    T_NESTTYPE = 0x9,
    T_VFUNCTAB = 0xA,
    T_FRIENDCLS = 0xB,
};


enum tds_sized_stdtypes {

    SST_INT = 0x10,
    SST_UINT = 0x20,
    SST_BOOL = 0x30,
    SST_REAL = 0x40,
    SST_COMPLEX = 0x50,
};


enum tds_stdint_sizes_types {

    SIS_8 = 0x0,
    SIS_16 = 0x1,
    SIS_32 = 0x2,
    SIS_64 = 0x3,
};

enum tds_stdfloat_sizes_types {

    SFS_32 = 0x0,
    SFS_64 = 0x1,
    SFS_80 = 0x2,
    SFS_128 = 0x3,
    SFS_48 = 0x4,
};

enum tds_std_types {

    ST_NONE = 0x0,
    // ST_ABS = 0x1,
    // ST_SEGMENT = 0x2,
    ST_VOID = 0x3,
    ST_BASIC_CURRENCY = 0x4,
    ST_NEAR_BASIC_STRING = 0x5,
    ST_FAR_BASIC_STRING = 0x6,
    // ST_CV3X =0x7,
    // 0x8-0xF same as 0x0-0x7
    ST_INT8 = 0x10,
    ST_INT16 = 0x11,
    ST_INT32 = 0x12,
    ST_INT64 = 0x13,
    // 0x14-17 interpreated as *??* int, looks like garbage
    // 0x18-1F same as 10-18
    ST_UINT8 = 0x20,
    ST_UINT16 = 0x21,
    ST_UINT32 = 0x22,
    ST_UINT64 = 0x23,
    // 0x24-2F same story
    ST_BOOL8 = 0x30,
    ST_BOOL16 = 0x31,
    ST_BOOL32 = 0x32,
    ST_BOOL64 = 0x33,
    // 0x34-3F same story
    ST_REAL32 = 0x40,
    ST_REAL64 = 0x41,
    ST_REAL80 = 0x42,
    ST_REAL128 = 0x43,
    ST_REAL48 = 0x44,
    // 0x45-4F seems unused
    ST_COMPLEX32 = 0x50,
    ST_COMPLEX64 = 0x51,
    ST_COMPLEX80 = 0x52,
    ST_COMPLEX128 = 0x53,
    ST_COMPLEX48 = 0x54,
    // 0x55-57 looks unused
    // 0x58-5F copy
    ST_BIT = 0x60,
    ST_PASCHAR = 0x61,
    // ST_UNDEFEXTERNAL = 0x62,
    // 0x63-67 seems unused
    // 0x68-6F copy again
    ST_CHAR = 0x70,
    ST_WCHAR = 0x71,
    ST_RINT16 = 0x72,
    ST_RUINT16 = 0x73,
    ST_RINT32 = 0x74,
    ST_RUINT32 = 0x75,
    ST_RINT64 = 0x76,
    ST_RUINT64 = 0x77,
    // 0x78-7F copy
};


enum tds_stdpointer_types {

    SPT_NEAR_PTR = 0x100,
    SPT_FAR_PTR  = 0x200,
    SPT_HUGE_PTR = 0x300,
    SPT_NEAR_PTR32 = 0x400,
    SPT_FAR_PTR32  = 0x500,
    SPT_NEAR_PTR64 = 0x600,
};

enum tds_call_type {

    CT_NEAR_CDECL = 0x0,
    CT_FAR_CDECL = 0x1,
    CT_NEAR_PASCAL = 0x2,
    CT_FAR_PASCAL = 0x3,
    CT_NEAR_FASTCALL = 0x4,
    CT_FAR_FASTCALL = 0x5,
    CT_PCODE = 0x6,
    CT_NEAR_STDCALL = 0x7,
    CT_FAR_STDCALL = 0x8,
    CT_NEAR_SYSCALL = 0x9,
    CT_FAR_SYSCALL = 0xA,
    CT_THIS_CALL = 0xB,
    CT_NEAR_FASTCALL2 = 0xC,
};

enum tds_access_type {

    AT_NONE = 0,
    AT_PRIVATE = 1,
    AT_PROTECTED = 2,
    AT_PUBLIC = 3,
};

enum tds_pointer_types {

    PT_NEAR16 = 0x0,
    PT_FAR16 = 0x1,
    PT_HUGE16 = 0x2,
    PT_BASED_ON_SEGMENT = 0x3,
    PT_BASED_ON_VALUE = 0x4,
    PT_BASED_ON_SEGMENT_OF_VALUE = 0x5,
    PT_BASED_ON_ADDRESS_OF_SYMBOL = 0x6,
    PT_BASED_ON_SEG_OF_SYMBOL = 0x7,
    PT_BASED_ON_TYPE = 0x8,
    PT_BASED_ON_SELF = 0x9,
    PT_NEAR32 = 0xA,
    PT_FAR32 = 0xB,
};

enum tds_pointer_modes {

    PM_SIMPLE = 0,
    PM_REFERENCE = 1,
    PM_TO_DATA_MEMBER = 2,
    PM_TO_METHOD = 3,
};

enum tds_modifier_flags {

    MOD_CONST = 0x1,
    MOD_VOLATILE = 0x2,
};


enum tds_machine_types {

    Intel8080 = 0x0,
    Intel8086 = 0x1,
    Intel80286 = 0x2,
    Intel80386 = 0x3,
    Intel80486 = 0x4,
    IntelPentium = 0x5,
    MIPS_R4000 = 0x10,
    MC68000 = 0x20,
    MC68010 = 0x21,
    MC68020 = 0x22,
    MC68030 = 0x23,
    MC68040 = 0x24,
    DEC_Alpha = 0x30,
};

enum tds_language_types {

    LANG_C = 0x0,
    LANG_CPP = 0x1,
    LANG_FORTRAN = 0x2,
    LANG_MASM = 0x3,
    LANG_PASCAL = 0x4,
    LANG_BASIC = 0x5,
    LANG_COBOL = 0x6,
};

enum tds_memory_model_types {

    MODEL_NEAR = 0,
    MODEL_FAR = 1,
    MODEL_HUGE = 2,
};

enum tds_floating_types {

    FPU_HARDWARE = 0,
    FPU_EMULATION = 1,
    FPU_ALTMATH = 2,
};

enum tds_method_storage_types {

    MST_NONE = 0,
    MST_VIRTUAL = 1,
    MST_STATIC = 2,
    MST_FRIEND = 3,
    MST_INTRODUCING_VIRTUAL = 4,
    MST_PURE_VIRTUAL = 5,
    MST_PURE_INTRODUCING_VIRTUAL = 6,
};

enum tds_virt_tbl_desctiptor_type
{
    VTDT_NEAR16 = 0x0,
    VTDT_FAR16 = 0x1,
    VTDT_THIN = 0x2,
    VTDT_ADDR_POINT_DISPLACEMENT_OUTERMOST_CLASS = 0x3,
    VTDT_FAR_PTR_METACLASS_DESCR = 0x4,
    VTDT_NEAR32 = 0x5,
    VTDT_FAR32 = 0x6,
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
    uint32_t proc_size;
    uint32_t debug_start;
    uint32_t debug_proc_size;
    uint32_t start;
    uint16_t segment;
    uint32_t type;
    uint8_t  nearfar;
    uint8_t  reserved;
    uint16_t name;
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

void fuku_tds::parse_modules(const uint8_t * start, const uint8_t * end) {

    const tds_module_subsection * mod_ss = (const tds_module_subsection *)start;

    for (uint32_t seg_idx = 0; seg_idx < mod_ss->segments_count;seg_idx++) {

        fuku_tds_segment segment;
        segment.segment_name = get_name_by_id(mod_ss->name);
        segment.segment_id = mod_ss->segments[seg_idx].index;
        segment.segment_start = mod_ss->segments[seg_idx].start;
        segment.segment_size = mod_ss->segments[seg_idx].end;

        this->segments.push_back(segment);
    }
}

void fuku_tds::parse_symbols(const uint8_t * start, const uint8_t * end) {

    const uint8_t * pos = start;
    const tds_ssearch * symbolSearch;

    while (pos != end) {

        uint32_t size = *(uint16_t*)pos; pos += sizeof(uint16_t);
        uint32_t type = *(uint16_t*)pos; pos += sizeof(uint16_t);

        switch (type & 0xFF00) {
        case 0:
            switch (type & 0xFF) {
            case S_CONST: {
                const tds_sconst * _const = (const tds_sconst *)pos;

                fuku_tds_const const_item;
                const_item.const_name = get_name_by_id(_const->name);
                const_item.const_size = size - offsetof(tds_sconst, value) - 2;
                const_item.value.resize(const_item.const_size);
                memcpy(const_item.value.data(), _const->value, const_item.const_size);

                this->consts.push_back(const_item);
                break;
            }
            case S_PCONSTANT: {
                const tds_spconstant * _const = (const tds_spconstant *)pos;

                fuku_tds_const const_item;
                const_item.const_name = get_name_by_id(_const->name);
                const_item.const_size = size - offsetof(tds_spconstant, value) - 2;
                const_item.value.resize(const_item.const_size);
                memcpy(const_item.value.data(), _const->value, const_item.const_size);

                this->consts.push_back(const_item);
                break;
            }
            default:
                break;
            }
            break;
        case 0x100:
            break;
        case 0x200:
            switch (type & 0xFF) {
            case S_LDATA: {
                const tds_sdata32 * data = (const tds_sdata32 *)pos;
                fuku_tds_data data_item;
                data_item.data_name = get_name_by_id(data->name);
                data_item.segment_id = data->segment;
                data_item.data_start = data->offset;

                this->datas.push_back(data_item);
                break;
            }
            case S_GDATA: {
                const tds_sdata32 * data = (const tds_sdata32 *)pos;
                fuku_tds_data data_item;
                data_item.data_name = get_name_by_id(data->name);
                data_item.segment_id = data->segment;
                data_item.data_start = data->offset;

                this->datas.push_back(data_item);
                break;
            }
            case S_LPROC: {
                const tds_sproc32 * proc = (const tds_sproc32 *)pos;

                fuku_tds_function func;
                func.function_name = get_name_by_id(proc->name);
                func.segment_id = proc->segment;
                func.function_start = proc->start;
                func.function_size = proc->proc_size;
                func.function_debug_size = proc->debug_proc_size;

                this->functions.push_back(func);
                break;
            }
            case S_GPROC: {
                const tds_sproc32 * proc = (const tds_sproc32 *)pos;

                fuku_tds_function func;
                func.function_name = get_name_by_id(proc->name);
                func.segment_id = proc->segment;
                func.function_start = proc->start;
                func.function_size = proc->proc_size;
                func.function_debug_size = proc->debug_proc_size;

                this->functions.push_back(func);
                break;
            }
            default:
                break;
            }
            break;
        default:
            break;
        }
        pos += size - 2;
    }
}

void fuku_tds::parse_alignsym(uint8_t * start, uint8_t * end, int moduleIndex) {
    uint8_t * pos = start;
    uint32_t unknown1 = *(uint32_t*)pos; pos += sizeof(uint32_t);
    parse_symbols(pos, end);
}



void fuku_tds::parse_globalsym(uint8_t * start) {

    const tds_global_sym_header * hdr = (tds_global_sym_header*)(start);
    const uint8_t * pos = start + sizeof(tds_global_sym_header);
    parse_symbols(pos, pos + hdr->cb_symbols);
}

void fuku_tds::parse_src_module(uint8_t * start, uint8_t * end) {

    const uint8_t * pos = start;
    uint16_t number_files = *(uint16_t*)pos; pos += sizeof(uint16_t);
    uint16_t number_ranges = *(uint16_t*)pos; pos += sizeof(uint16_t);
    const uint32_t * filesOffsets = (const uint32_t *)(pos);
    const uint32_t * ranges = (const uint32_t *)(pos + 4 * number_files);
    const uint16_t * segs = (const uint16_t *)(pos + 4 * number_files + 8 * number_ranges);

    for (uint32_t file_idx = 0; file_idx < number_files; file_idx++) {

        pos = start + filesOffsets[file_idx];
        uint16_t num_file_ranges = *(uint16_t*)pos; pos += sizeof(uint16_t);
        int name = *(uint32_t*)pos; pos += sizeof(uint32_t);

        const uint32_t* numbersOffsets = (const uint32_t*)(pos);
        const uint32_t* fileRanges = (const uint32_t*)(pos + 4 * num_file_ranges);

        fuku_tds_linenumbers base_linenumbers;
        base_linenumbers.file_name = get_name_by_id(name);

        for (uint32_t range_idx = 0; range_idx < num_file_ranges; range_idx++) {

            pos = start + numbersOffsets[range_idx];
            uint16_t segment_id = *(uint16_t*)pos; pos += sizeof(uint16_t);
            uint16_t lines_number = *(uint16_t*)pos; pos += sizeof(uint16_t);

            fuku_tds_linenumbers_block linenumbers_block;
            linenumbers_block.segment_id  = segment_id;
            linenumbers_block.block_start = fileRanges[range_idx * 2];
            linenumbers_block.block_end   = fileRanges[range_idx * 2 + 1];
        
            const uint32_t * offsets = (const uint32_t *)(pos);
            const uint16_t * lineNumbers = (const uint16_t *)(pos + 4 * lines_number);

            for (uint32_t lines_idx = 0; lines_idx < lines_number; lines_idx++) {
                linenumbers_block.line_numbers[lineNumbers[lines_idx]] = offsets[lines_idx]; 
            }

            base_linenumbers.blocks.push_back(linenumbers_block);
        }

        this->linenumbers.push_back(base_linenumbers);
    }
}


/*

std::string get_type_name(uint32_t type) {
    std::string ret;

    if (type < 0x1000) {

        if (type & TYPE_POINTER_MASK) {

            switch (type & TYPE_POINTER_MASK) {

            case SPT_NEAR_PTR:      {ret += "near"; break; }
            case SPT_FAR_PTR:       {ret += "near"; break;}
            case SPT_HUGE_PTR:      {ret += "huge"; break;}
            case SPT_NEAR_PTR32:    {ret += "near32"; break; }
            case SPT_FAR_PTR32:     {ret += "far32"; break; }
            case SPT_NEAR_PTR64:    {ret += "near64"; break; }
            }
            ret += " *";
        }

        switch (type & 0xff) {

        case ST_NONE:                   {ret += "none"; break; }
        case ST_VOID:                   {ret += "void"; break; }
        case ST_BASIC_CURRENCY:         {ret += "BasicCurr"; break; }
        case ST_NEAR_BASIC_STRING:      {ret += "NearBasStr"; break; }
        case ST_FAR_BASIC_STRING:       {ret += "FarBasStr"; break; }
        case ST_INT8:                   {ret += "int8"; break; }
        case ST_INT16:                  {ret += "int16"; break; }
        case ST_INT32:                  {ret += "int32"; break; }
        case ST_INT64:                  {ret += "int64"; break; }
        case ST_UINT8:                  {ret += "uint8"; break; }
        case ST_UINT16:                 {ret += "uint16"; break; }
        case ST_UINT32:                 {ret += "uint32"; break; }
        case ST_UINT64:                 {ret += "uint64"; break; }
        case ST_BOOL8:                  {ret += "bool8"; break; }
        case ST_BOOL16:                 {ret += "bool16"; break; }
        case ST_BOOL32:                 {ret += "bool32"; break; }
        case ST_BOOL64:                 {ret += "bool64"; break; }
        case ST_REAL32:                 {ret += "real32"; break; }
        case ST_REAL64:                 {ret += "real64"; break; }
        case ST_REAL80:                 {ret += "real80"; break; }
        case ST_REAL128:                {ret += "real128"; break; }
        case ST_REAL48:                 {ret += "real48"; break; }
        case ST_COMPLEX32:              {ret += "complex32"; break; }
        case ST_COMPLEX64:              {ret += "complex64"; break; }
        case ST_COMPLEX80:              {ret += "complex80"; break; }
        case ST_COMPLEX128:             {ret += "complex128"; break; }
        case ST_COMPLEX48:              {ret += "complex48"; break; }
        case ST_BIT:                    {ret += "Bit"; break; }
        case ST_PASCHAR:                {ret += "PasChar"; break; }
        case ST_CHAR:                   {ret += "char"; break; }
        case ST_WCHAR:                  {ret += "wchar"; break; }
        case ST_RINT16:                 {ret += "rint16"; break; }
        case ST_RUINT16:                {ret += "ruint16"; break; }
        case ST_RINT32:                 {ret += "rint32"; break; }
        case ST_RUINT32:                {ret += "ruint32"; break; }
        case ST_RINT64:                 {ret += "rint64"; break; }
        case ST_RUINT64:                {ret += "ruint64"; break; }
        default: {
            break;
        }

        }
    }

    return ret;
}



std::string get_calltype_name(uint32_t type) {
    std::string ret;

    if ((type & ~FT_CALL_TYPE_MASK) & ~FT_VALID_FLAGS) {
        return std::string();
    }

    if (type & FT_VARARGS) {
        ret += "variable args ";
    }

    if (type & FT_FAST_THIS) {
        ret += "fast this ";
    }

    switch (type & FT_CALL_TYPE_MASK)
    {
    case CT_NEAR_CDECL:     {ret += "near cdecl"; break; }
    case CT_FAR_CDECL:      {ret += "far cdecl"; break; }
    case CT_NEAR_PASCAL:    {ret += "near pascal"; break; }
    case CT_FAR_PASCAL:     {ret += "far pascal"; break; }
    case CT_NEAR_FASTCALL:  {ret += "near fastcall"; break; }
    case CT_FAR_FASTCALL:   {ret += "far fastcall"; break; }
    case CT_PCODE:          {ret += "Pcode"; break; }
    case CT_NEAR_STDCALL:   {ret += "near stdcall"; break; }
    case CT_FAR_STDCALL:    {ret += "far stdcall"; break; }
    case CT_NEAR_SYSCALL:   {ret += "near syscall"; break; }
    case CT_FAR_SYSCALL:    {ret += "far syscall"; break; }
    case CT_THIS_CALL:      {ret += "this call"; break; }
    case CT_NEAR_FASTCALL2: {ret += "near fastcall2"; break; }
    default: {
        break;
    }
    }
    return ret;
}



std::string access_to_string(uint32_t accessType) {
    switch (accessType & 0x3) {
    case AT_NONE:       { return "none"; }
    case AT_PRIVATE:    { return "private"; }
    case AT_PROTECTED:  { return "protected"; }
    case AT_PUBLIC:     { return "public"; }
    default: {
        return std::string();
    }
    }
}



std::string modtype_to_string(uint32_t type) {
    switch (type) {
    case MOD_CONST:     { return "const"; }
    case MOD_VOLATILE:  { return "volatile"; }
    default: {
        return std::string();
    }
    }
}



std::string ptrtype_to_string(uint32_t type) {

    switch (type) {
    case PT_NEAR16:                     { return "near16"; }
    case PT_FAR16:                      { return "far16"; }
    case PT_HUGE16:                     { return "huge16"; }
    case PT_BASED_ON_SEGMENT:           { return "based on segment"; }
    case PT_BASED_ON_VALUE:             { return "based on value"; }
    case PT_BASED_ON_SEGMENT_OF_VALUE:  { return "based on segment value"; }
    case PT_BASED_ON_ADDRESS_OF_SYMBOL: { return "based on address of symbol"; }
    case PT_BASED_ON_SEG_OF_SYMBOL:     { return "based on seg of symbol"; }
    case PT_BASED_ON_TYPE:              { return "based on type"; }
    case PT_BASED_ON_SELF:              { return "based on self"; }
    case PT_NEAR32:                     { return "near32"; }
    case PT_FAR32:                      { return "far32"; }
    default: {
        return std::string();
    }
    }
}


std::string ptrmod_to_string(uint32_t type) {
    switch (type){
    case PM_SIMPLE:         { return ""; }
    case PM_REFERENCE:      { return "&"; }
    case PM_TO_DATA_MEMBER: { return "to data member"; }
    case PM_TO_METHOD:      { return "to method"; }
    default: {
        return std::string();
    }
    }
}

std::string methodstor_to_string(uint32_t type) {

    switch (type)
    {
    case MST_NONE: { return "vanilla"; }
    case MST_VIRTUAL: { return "virtual"; }
    case MST_STATIC: { return "static"; }
    case MST_FRIEND: { return "friend"; }
    case MST_INTRODUCING_VIRTUAL: { return "introducing virtual"; }
    case MST_PURE_VIRTUAL: { return "pure virtual"; }
    case MST_PURE_INTRODUCING_VIRTUAL: { return "pure introducing virtual"; }
    default: {
        return std::string();
    }
        
    }
}

std::string PrintEscapedField(tds_escaped_field fld) {

    std::string ret;
    char esc_buf[20] = { 0 };

    switch (fld.size)
    {
    case 2:
        _itoa_s(*(uint16_t*)&fld.ptr, esc_buf, 16);
        ret = esc_buf;
        break;
    case 4:
        _itoa_s(*(uint32_t*)&fld.ptr, esc_buf, 16);
        ret = esc_buf;
        break;
    default:
        break;
    }

    return ret;
}

void PrintStructFlags(unsigned flags)
{
    cout << "  Packed: " << ((flags & CF_PACKED) ? "Yes" : "No") <<
        "  Constructors: " << ((flags & CF_CONSTRUCTORS) ? "Yes" : "No") <<
        "  Destructors: " << ((flags & CF_DESTRUCTORS) ? "Yes" : "No") <<
        "  Overloaded operators: " << ((flags & CF_OVERLOADED_OPERATORS) ? "Yes" : "No") << endl;
    cout << "  Is nested: " << ((flags & CF_IS_NESTED) ? "Yes" : "No") <<
        "  Nested classes: " << ((flags & CF_NESTED_CLASSES) ? "Yes" : "No") <<
        "  Overload assignments: " << ((flags & CF_NESTED_CLASSES) ? "Yes" : "No") << endl;
    cout << "  Casting methods: " << ((flags & CF_CASTING_METHODS) ? "Yes" : "No") <<
        "  Forward Ref: " << ((flags & CF_FORWARD_REFERENCE) ? "Yes" : "No") << endl;
}


inline tds_escaped_field EatEscapedField(const uint8_t *& pos)
{
    tds_escaped_field result = {0 ,0};
    int prefix = *reinterpret_cast<const short*>(pos);
    pos += sizeof(uint16_t);

    if (prefix >= 0) {
        result.ptr = (const char*)pos;
        result.size = sizeof(uint16_t);
        return result;
    }
    else {
        switch (prefix & 0xFF)
        {
        case 1:
        case 2:
            result.ptr = (const char*)pos;
            result.size = sizeof(uint16_t);
            pos += sizeof(uint16_t);
            return result;
        case 3:
        case 4:
            result.ptr = (const char*)pos;
            result.size = sizeof(uint32_t);
            pos += sizeof(uint32_t);
            return result;
        default:
            return result;
        }
    }
}


void fuku_tds::ParseArray(const uint8_t * start) {

    const tds_array * arr = reinterpret_cast<const tds_array *>(start);
    const uint8_t * pos = start + sizeof(tds_array);
    cout << "  Type: " << arr->element_type << "  Indexed by: " << arr->indexer_type << "  Name: " << arr->name << endl;
    cout << "  Size: ";
    PrintEscapedField(EatEscapedField(pos));
    cout << "  Elements: ";
    PrintEscapedField(EatEscapedField(pos));
    cout << endl;
}



void fuku_tds::ParseStruct(const uint8_t * start, unsigned type)
{
    const uint8_t * pos = start;
    tds_escaped_field size;
    switch (type)
    {
    case T_CLASS:
    case T_STRUCT:
        const tds_class * cls;
        cls = reinterpret_cast<const tds_class *>(pos);
        pos += sizeof(tds_class);

        size = EatEscapedField(pos);
        if (cls->flags & ~CF_VALID_FLAGS) {
            return;
        }

        if (1)
        {
            cout << "  Fields: " << cls->num_members << "  FieldIdx: " << cls->field_index << "  Name: " << get_name_by_id(cls->name) << " [" << cls->name << "]" << endl;
            cout << "  Containing Class: " << cls->containing_class << "  Length: ";
            PrintEscapedField(size);
            cout << endl;
            cout << "  Derivation list: " << cls->derivation_list << "  VTable: " << cls->vtable << endl;
            PrintStructFlags(cls->flags);
        }
        break;
    case T_UNION:
        const tds_union * un;
        un = reinterpret_cast<const tds_union *>(pos);
        pos += sizeof un;
        size = EatEscapedField(pos);
        if (un->flags & ~CF_VALID_FLAGS) {
            return;
        }
        if (1)
        {
            cout << "  Fields: " << un->num_members << "  FieldIdx: " << un->field_index << "  Name: " << get_name_by_id(un->name) << " [" << un->name << "]" << endl;
            cout << "  Containing Class: " << un->containing_class << "  Length: ";
            PrintEscapedField(size);
            cout << endl;
            PrintStructFlags(un->flags);
        }
        break;
    default:
        return;
    }
}



void fuku_tds::ParseVirtTblShape(const uint8_t * start)
{
    const uint8_t * pos = start;
    int num = *(uint16_t*)pos; pos += sizeof(uint16_t);
    for (int i = 0; i < num; i++)
    {
        unsigned int byte = pos[i / 2];
        if (i % 2 == 1)
        {
            byte >>= 4;
        }
        byte &= 0xF;
        cout << "  Descriptor: ";
        switch (byte)
        {
        case VTDT_NEAR16: cout << "near"; break;
        case VTDT_FAR16: cout << "far"; break;
        case VTDT_THIN: cout << "thin"; break;
        case VTDT_ADDR_POINT_DISPLACEMENT_OUTERMOST_CLASS: cout << "addr point displacement to outermost class"; break;
        case VTDT_FAR_PTR_METACLASS_DESCR: cout << "far * metaclass descriptor"; break;
        case VTDT_NEAR32: cout << "near32"; break;
        case VTDT_FAR32: cout << "far32"; break;
        default:
            break;
        }
        cout << endl;
    }
}


void fuku_tds::ParseArgList(const uint8_t * start)
{
    const uint8_t * pos = start;
    int num = *(uint16_t*)pos; pos += sizeof(uint16_t);
    const int * types = reinterpret_cast<const int *>(pos);
    for (int i = 0; i < num; i++)
    {
        cout << "  Type: ";
        cout << get_type_name(types[i]);
        cout << endl;
    }
}

void fuku_tds::ParseFieldList(const uint8_t * start, const uint8_t * end) {

    const uint8_t * pos = start;
    while (pos < end) {

        int type = *(uint16_t*)pos; pos += sizeof(uint16_t);
        if (type == 0xf1f2u) {
            continue;
        }

        const tds_bclass * bcls;
        const tds_vbclass * vbcls;
        const tds_enumerate * enumr;
        const tds_member * member;
        const tds_static_member * stMember;
        const tds_method * method;
        const tds_nest_type * nestType;
        if (1)
            cout << "  " << get_type_name(type);

        int vtabType;
        int vtabOffset;
        int continuationIndex;
        int enumType;
        int enumValue;
        switch (type & TD_TYPE_MASK)
        {
        case T_BCLASS:
            bcls = reinterpret_cast<const tds_bclass *>(pos);
            if (1)
                cout << "  Type: " << bcls->index << "  Offset: " << bcls->offset << "  Access: " << access_to_string(bcls->access);
            pos += sizeof(tds_bclass);
            break;
        case T_VBCLASS:
        case T_IVBCLASS:
            vbcls = reinterpret_cast<const tds_vbclass *>(pos);
            if (vbcls->unknown1 != 0x8001u)
                cout << "catch";
            if (1)
            {
                cout << "  Base: " << vbcls->base << "  Virtual Base: " << vbcls->virtual_base << "  Access: " << access_to_string(vbcls->access) << endl;
                cout << "    Virtual Base Pointer Offset: " << vbcls->virt_base_ptr_offset << "  Virtual Base Index: " << vbcls->virt_base_index;
            }
            pos += sizeof(tds_vbclass);
            break;
        case T_ENUMERATE:
            enumr = reinterpret_cast<const tds_enumerate *>(pos);
            pos += sizeof(tds_enumerate);
            enumType = *(uint16_t*)pos; pos += sizeof(uint16_t);
            switch (enumType)
            {
            case 0x8002:
                enumValue = *(uint16_t*)pos; pos += sizeof(uint16_t);
                break;
            case 0x8004:
                enumValue = *(uint32_t*)pos; pos += sizeof(uint32_t);
                break;
            default:
                enumValue = enumType;
            }
            if (1)
                cout << "  Attr: " << enumr->attribs << "  Value: " << enumValue << "  Name: " << get_name_by_id(enumr->name) << " [" << enumr->name << "]  Browser offset: " << enumr->browser_offset;
            break;
        case T_INDEX:
            continuationIndex = *(uint32_t*)pos; pos += sizeof(uint32_t);
            if (1)
                cout << "	 continuation index: " << continuationIndex;
            break;
        case T_MEMBER:
            member = reinterpret_cast<const tds_member *>(pos);
            if (1)
                cout << "  Type: " << member->type << "  Offs: " << member->offset << "  Access: " << access_to_string(member->access) << "  Name: " << get_name_by_id(member->name) << " [" << member->name << "]  Browser offset: " << member->browser_offset;
            pos += sizeof(tds_member);
            break;
        case T_STMEMBER:
            stMember = reinterpret_cast<const tds_static_member *>(pos);
            if (1)
                cout << "  Type: " << stMember->type << "  Access: " << access_to_string(stMember->access) << "  Name: " << get_name_by_id(stMember->name) << " [" << stMember->name << "]  Browser offset: " << stMember->browser_offset;
            pos += sizeof(tds_static_member);
            break;
        case T_METHOD:
            method = reinterpret_cast<const tds_method *>(pos);
            if (1)
                cout << "  count: " << method->count << "  MethodIdx: " << method->index << "  Name: " << get_name_by_id(method->name) << " [" << method->name << "]";
            pos += sizeof(tds_method);
            break;
        case T_NESTTYPE:
            nestType = reinterpret_cast<const tds_nest_type *>(pos);
            if (1)
                cout << "  Index: " << nestType->index << "  Name: " << get_name_by_id(nestType->name) << " [" << nestType->name << "]  Browser offset: " << nestType->browser_offset;
            pos += sizeof(tds_nest_type);
            break;
        case T_VFUNCTAB:
            vtabType = *(uint32_t*)pos; pos += sizeof(uint32_t);
            vtabOffset = *(uint16_t*)pos; pos += sizeof(uint16_t);
            if (1)
                cout << "  Type: " << vtabType << "  vtab offs: " << vtabOffset;
            break;
        default:
            break;
        }
        if (1)
            cout << endl;
    }
}


void fuku_tds::ParseMethodList(const uint8_t * start, const uint8_t * end) {

    const uint8_t * pos = start;
    while (pos != end) {

        const tds_method_lstitem * met = reinterpret_cast<const tds_method_lstitem *>(pos);
        cout << "  Type: " << met->type << "  Access: " << access_to_string(met->access_storage) << "  Prop: " <<
            methodstor_to_string(METHOD_STORAGE_FIELD(met->access_storage));

        if (METHOD_STORAGE_FIELD(met->access_storage) == MST_VIRTUAL || METHOD_STORAGE_FIELD(met->access_storage) == MST_INTRODUCING_VIRTUAL ||
            METHOD_STORAGE_FIELD(met->access_storage) == MST_PURE_VIRTUAL || METHOD_STORAGE_FIELD(met->access_storage) == MST_PURE_INTRODUCING_VIRTUAL)
        {
            cout << "  Vtab Offs: " << met->vtab_offset;
            pos += 14;
        }
        else
        {
            pos += 10;
        }
        cout << "  Browser offset: " << met->browser_offset << endl;

        if (METHOD_FLAGS_FIELD(met->access_storage) & ~MDF_VALID_FLAGS) {
            return;
        }

        cout << "  Default1: " << (met->access_storage & MDF_DEFAULT1 ? "yes" : "no") <<
            "  Overloaded operator: " << (met->access_storage & MDF_OPERATOR_OVERLOAD ? "yes" : "no") <<
            "  Conversion operator: " << (met->access_storage & MDF_CONVERSION_OPERATOR ? "yes" : "no") << endl;
        cout << "  Constructor: " << (met->access_storage & MDF_CONSTRUCTOR ? "yes" : "no") <<
            "  Destructor: " << (met->access_storage & MDF_DESTRUCTOR ? "yes" : "no") <<
            "  Default2: " << (met->access_storage & MDF_DEFAULT2 ? "yes" : "no") << endl;
    }
}

void fuku_tds::ParseGlobalTypes(uint8_t * start) {

    const uint8_t * pos = start;
    int unknown = *(uint32_t*)pos; pos += sizeof(uint32_t);
    size_t num = *(uint32_t*)pos; pos += sizeof(uint32_t);
    const int * offsets = reinterpret_cast<const int *>(pos);

    for (size_t i = 0; i < num; i++) {

        const tds_modifier * mod;
        const tds_pointer * ptr;
        const tds_enum * en;
        const tds_procedure * proc;
        const tds_member_function * mfunc;

        pos = start + offsets[i];
        int len = *(uint16_t*)pos; pos += sizeof(uint16_t);
        int type = *(uint16_t*)pos; pos += sizeof(uint16_t);
        if (1)
            cout << start + offsets[i] - this->tds_data.data() << "  Type: " << (i + 0x1000) << "  Len: " << len << "  " << get_type_name(type) << endl;
        switch (type & TD_CLASS_MASK)
        {
        case TDC_ROOT:
            switch (type & TD_TYPE_MASK)
            {
            case T_MODIFIER:
                mod = reinterpret_cast<const tds_modifier *>(pos);
                if (1)
                {
                    cout << "  Type: " << mod->type << "  " <<
                        ((mod->mod & MOD_CONST) ? "const " : "") <<
                        ((mod->mod & MOD_VOLATILE) ? "volatile" : "") << endl;
                }
                break;
            case T_POINTER:
                ptr = reinterpret_cast<const tds_pointer *>(pos);
                ptrtype_to_string(PTR_TYPE_FIELD(ptr->ptr_type_mod));
                if (1)
                {
                    cout << "  " << ptrtype_to_string(PTR_TYPE_FIELD(ptr->ptr_type_mod)) << " " << ptrmod_to_string(PTR_MODE_FIELD(ptr->ptr_type_mod)) <<
                        "  (PtrType: " << PTR_TYPE_FIELD(ptr->ptr_type_mod) << "  PtrMode: " << PTR_MODE_FIELD(ptr->ptr_type_mod) << ")" << endl;
                    cout << "  Points to: ";
                    cout << get_type_name(ptr->points_to);
                    cout << endl;
                    if (PTR_MODE_FIELD(ptr->ptr_type_mod) == PM_TO_DATA_MEMBER ||
                        PTR_MODE_FIELD(ptr->ptr_type_mod) == PM_TO_METHOD)
                    {
                        cout << "  Member/Method class: " << ptr->_class << " Format: " << ptr->format << endl;
                    }
                }
                break;
            case T_ARRAY:
                ParseArray(pos);
                break;
            case T_CLASS:
            case T_STRUCT:
            case T_UNION:
                ParseStruct(pos, type);
                break;
            case T_ENUM:
                en = reinterpret_cast<const tds_enum *>(pos);
                if (1)
                {
                    cout << "  Count: " << en->count << "  Type: ";
                    cout << get_type_name(en->type);
                    cout << "  Fields: " << en->fields << "  Class: " << en->_class << "  Name: " << get_name_by_id(en->name) << " [" << en->name << "]" << endl;
                }
                break;
            case T_PROCEDURE:
                proc = reinterpret_cast<const tds_procedure *>(pos);
                cout << "  ";
                cout << get_calltype_name(proc->call_type);
                cout << " returns: ";
                cout << get_type_name(proc->type);
                cout << endl << "  Params: " << proc->params << "  ArgList: " << proc->arg_list << endl;
                break;
            case T_MFUNCTION:
                mfunc = reinterpret_cast<const tds_member_function *>(pos);
                cout << "  ";
                cout << get_calltype_name(mfunc->call_type);
                cout << " returns: ";
                cout << get_type_name(mfunc->type);
                cout << endl << "  Class: " << mfunc->_class << "  'this': " << mfunc->_this << "  Params: " << mfunc->params << "  Args: " << mfunc->arg_list << "  `this' adjust: " << mfunc->adjust << endl;
                break;
            case T_VTSHAPE:
                ParseVirtTblShape(pos);
                break;
            default:
                break;
            }
            break;
        case TDC_LIST:
            switch (type & TD_TYPE_MASK)
            {
            case T_ARGLIST:
                ParseArgList(pos);
                break;
            case T_FIELDLIST:
                ParseFieldList(pos, pos + len - 2);
                break;
            case T_METHODLIST:
                ParseMethodList(pos, pos + len - 2);
                break;
            default:
                break;
            }
            break;
        default:
            break;
        }
        if (1)
            cout << endl;
    }
}*/



fuku_tds::fuku_tds()
{
}


fuku_tds::~fuku_tds()
{
}

fuku_tds_result fuku_tds::load_from_file(const std::string& tds_path) {

    fuku_tds_result result;
    std::vector<uint8_t> data;

    FILE* hfile;

    fopen_s(&hfile, tds_path.c_str(), "rb");

    if (hfile != nullptr) {

        fseek(hfile, 0, SEEK_END);
        size_t file_size = ftell(hfile);
        fseek(hfile, 0, SEEK_SET);

        data.reserve(file_size);
        data.resize(file_size);

        if (fread((void*)data.data(), file_size, 1, hfile)) {
            result = load_from_data(data);
        }
        else {
            result = fuku_tds_result::tds_result_error;
        }

        fclose(hfile);
    }
    else {
        result = fuku_tds_result::tds_result_error;
    }

    return result;
}

fuku_tds_result fuku_tds::load_from_data(const std::vector<uint8_t>& tds_data) {

    this->names_pool.clear();
    this->tds_data.clear();
    this->segments.clear();
    this->linenumbers.clear();
    this->functions.clear();
    this->datas.clear();
    this->consts.clear();

    this->tds_data = tds_data;

    if (tds_data.size() < 0x100) { return fuku_tds_result::tds_result_error; }

    const tds_header * header = (const tds_header *)(tds_data.data());

    if (header->magic != 0x39304246/*FB09*/ && header->magic != 0x41304246/*FB0A*/) {
        return fuku_tds_result::tds_result_error;
    }

    if (*(uint32_t*)&tds_data.data()[tds_data.size()-8] != header->magic) {
        return fuku_tds_result::tds_result_error;
    }

    const tds_subsection_dir * s_section_dir = (const tds_subsection_dir *)(&tds_data.data()[header->subsection_offset]);
    const tds_subsection_dir_item * items = &s_section_dir->items[0];

    for (uint32_t i = 0; i < s_section_dir->num; i++) {
        const tds_subsection_dir_item * current_item = &items[i];

        if (current_item->type == sst_names) {
            load_names(&this->tds_data.data()[current_item->offset]);
            break;
        }
    }


    for (uint32_t i = 0; i < s_section_dir->num; i++) {
        const tds_subsection_dir_item * current_item = &items[i];

        switch (current_item->type) {
        
        case sst_module: {
            parse_modules(&this->tds_data.data()[current_item->offset], &this->tds_data.data()[current_item->offset + current_item->size]);

            break;
        }

        case sst_alignsym: {
            parse_alignsym(&this->tds_data.data()[current_item->offset], &this->tds_data.data()[current_item->offset + current_item->size],
                current_item->index);

            break;
        }

        case sst_srcmodule: {
            parse_src_module(&this->tds_data.data()[current_item->offset], &this->tds_data.data()[current_item->offset + current_item->size]);
            break;
        }

        case sst_globalsym: {
            parse_globalsym(&this->tds_data.data()[current_item->offset]);
            break;
        }
        case sst_globaltypes: {
            //  ParseGlobalTypes(&this->tds_data.data()[current_item->offset]);
            break;
        }

        default: {
            break;
        }
        }
    }

    std::sort(segments.begin(), segments.end(), [](fuku_tds_segment& lhs, fuku_tds_segment& rhs) {

        if (lhs.segment_id < rhs.segment_id) {
            return true;
        }
        else if (lhs.segment_id == rhs.segment_id &&
            lhs.segment_start < rhs.segment_start) {
            return true;
        }
        else {
            return false;
        }
    });

    std::sort(functions.begin(), functions.end(), [](fuku_tds_function& lhs, fuku_tds_function& rhs) {

        if (lhs.segment_id < rhs.segment_id) {
            return true;
        }
        else if (lhs.segment_id == rhs.segment_id &&
            lhs.function_start < rhs.function_start) {
            return true;
        }
        else {
            return false;
        }
    });

    std::sort(datas.begin(), datas.end(), [](fuku_tds_data& lhs, fuku_tds_data& rhs) {

        if (lhs.segment_id < rhs.segment_id) {
            return true;
        }
        else if (lhs.segment_id == rhs.segment_id &&
            lhs.data_start < rhs.data_start) {
            return true;
        }
        else {
            return false;
        }
    });

    return fuku_tds_result::tds_result_ok;
}

void fuku_tds::load_names(uint8_t * names_ptr) {
    this->names_pool.clear();

    uint8_t * current_pos = names_ptr;
    uint32_t names_count = *(uint32_t*)current_pos;
    current_pos += sizeof(uint32_t);

    for (uint32_t i = 0; i < names_count; i++) {
        size_t len = *(uint8_t*)current_pos;
        current_pos += sizeof(uint8_t);

        std::string name = (char*)current_pos;
        names_pool.push_back(name);

        current_pos += len+1;
    }
}

std::string fuku_tds::get_name_by_id(uint32_t id) const {
    if (id > 0 && id < names_pool.size()) {
        return names_pool[id - 1];
    }
    return std::string();
}

uint32_t fuku_tds::get_id_by_name(const std::string &name) const {

    for (uint32_t name_id = 0; name_id < names_pool.size(); name_id++) {
        if (name == names_pool[name_id]) {
            return name_id;
        }
    }

    return -1;
}

const std::vector<fuku_tds_segment>&     fuku_tds::get_segments() const {
    return this->segments;
}

const std::vector<fuku_tds_linenumbers>& fuku_tds::get_linenumbers() const {
    return this->linenumbers;
}

const std::vector<fuku_tds_function>&    fuku_tds::get_functions() const {
    return this->functions;
}

const std::vector<fuku_tds_data>&        fuku_tds::get_datas() const {
    return this->datas;
}

const std::vector<fuku_tds_const>&       fuku_tds::get_consts() const {
    return this->consts;
}
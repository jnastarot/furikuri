#pragma once


struct psyche_pcode_entry {
    uint32_t type;
    uint8_t size;
    uint64_t value;
};

struct psyche_pcode {
    uint32_t entry_rva;
    std::vector<psyche_pcode_entry> entries;
};


struct psyche_block_pcode_table {
    size_t   table_size;
    uint32_t table_rva;

    psyche_block* block;
    std::vector<std::pair<psyche_cmd*, psyche_pcode*>> cmds;
};


class psyche_pcode_manager {

    std::list<psyche_block_pcode_table>  block_pcode_table;
    std::list<psyche_pcode> cmd_pcode_table;

    std::map<psyche_block*, psyche_block_pcode_table*> block_link_table;
    std::map<psyche_cmd*, psyche_pcode*> cmd_link_table;
public:
    psyche_pcode_manager();
    ~psyche_pcode_manager();
 
public:
    
    void add_pcode(const psyche_block* block, psyche_cmd* cmd, const psyche_pcode& pcode_entry);

public:
    
    psyche_pcode * get_cmd_pcode(const psyche_cmd* cmd);
    const psyche_pcode * get_cmd_pcode(const psyche_cmd* cmd) const;

    psyche_block_pcode_table * get_block_pcode(const psyche_block* block);
    const psyche_block_pcode_table * get_block_pcode(const psyche_block* block) const;

    std::list<psyche_block_pcode_table>&  get_block_pcode_table();
    const std::list<psyche_block_pcode_table>&  get_block_pcode_table() const;

    std::list<psyche_pcode>& get_cmd_pcode_table();
    const std::list<psyche_pcode>& get_cmd_pcode_table() const;

    std::map<psyche_block*, psyche_block_pcode_table*>& get_block_link_table();
    const std::map<psyche_block*, psyche_block_pcode_table*>& get_block_link_table() const;

    std::map<psyche_cmd*, psyche_pcode*>& get_cmd_link_table();
    const std::map<psyche_cmd*, psyche_pcode*>& get_cmd_link_table() const;
};
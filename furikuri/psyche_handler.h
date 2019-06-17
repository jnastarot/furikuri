#pragma once

#pragma pack(push, 1)

struct psyche_handler_sign_op_header {
    uint32_t opcode;
    uint8_t size;
};

#pragma pack(pop)

struct psyche_handler_sign_extended {
    uint8_t arch;
    psyche_handler_sign_op_header op;
    psy_block_props properies;
};


class psyche_handler_sign {
    std::vector<uint8_t> sign;
    
    std::vector< psyche_cmd*> refs;

public:
    psyche_handler_sign();
    psyche_handler_sign(const psyche_handler_sign& sign);
    psyche_handler_sign(const psyche_block& parent_block, const psyche_cmd& cmd);
    ~psyche_handler_sign();

    psyche_handler_sign& operator=(const psyche_handler_sign& sign);
    psyche_handler_sign& operator=(std::pair<const psyche_block&, const psyche_cmd&> cmd);
    bool operator==(const psyche_handler_sign& sign) const;

    bool operator<(const psyche_handler_sign& sign) const;
public:
    void set_sign(std::vector<uint8_t>& sign);

public:
    void get_extended_sign(psyche_handler_sign_extended& sign) const;

    std::vector<uint8_t>& get_sign();
    const std::vector<uint8_t>& get_sign() const;

    std::vector< psyche_cmd*>& get_refs();
    const std::vector< psyche_cmd*>& get_refs() const;
};


class psyche_handler {
    size_t handler_label;
    std::map<uint32_t, uint64_t> handler_properies;

public:
    psyche_handler();
    psyche_handler(const psyche_handler& handler);
    ~psyche_handler();

    psyche_handler& operator=(const psyche_handler& handler);
public:
    void set_handler_label(size_t label);

public:
    size_t get_handler_label() const;

    std::map<uint32_t, uint64_t>& get_handler_properies();
    const std::map<uint32_t, uint64_t>& get_handler_properies() const;
};


class psyche_handler_manager {

    std::list<psyche_handler> handlers;
    
    std::map<psyche_handler_sign, std::vector<psyche_handler*>> handlers_link;
    std::map<psyche_handler*, psyche_handler_sign> handlers_sign_link;

    std::map<psyche_cmd*, psyche_handler*> handlers_link_table;

public:
    psyche_handler_manager();
    ~psyche_handler_manager();

public:

    void add_handler(const psyche_handler& handler, const psyche_handler_sign& signature);
    void link_cmd_handler(psyche_cmd* cmd, psyche_handler* handler);
  
public:

    std::vector<psyche_handler*>* get_handler_vec(const psyche_handler_sign& signature);
    const std::vector<psyche_handler*>* get_handler_vec(const psyche_handler_sign& signature) const;

    psyche_handler_sign* get_handler_sign(const psyche_handler* handler);
    const psyche_handler_sign* get_handler_sign(const psyche_handler* handler) const;

    psyche_handler* get_handler(psyche_cmd* cmd);
    const psyche_handler* get_handler(psyche_cmd* cmd) const;

    std::list<psyche_handler>& get_handlers();
    const std::list<psyche_handler>& get_handlers() const;

    std::map<psyche_handler_sign, std::vector<psyche_handler*>>& get_handlers_link();
    const std::map<psyche_handler_sign, std::vector<psyche_handler*>>& get_handlers_link() const;

    std::map<psyche_handler*, psyche_handler_sign>& get_handlers_sign_link();
    const std::map<psyche_handler*, psyche_handler_sign>& get_handlers_sign_link() const;

    std::map<psyche_cmd*, psyche_handler*>& get_handlers_link_table();
    const std::map<psyche_cmd*, psyche_handler*>& get_handlers_link_table() const;
};
#pragma once

class psyche_cmd_arg {
    uint8_t size;
    uint32_t type;

    uint64_t value;

public:
    psyche_cmd_arg();
    psyche_cmd_arg(const psyche_cmd_arg& arg);
    psyche_cmd_arg(uint8_t size, uint32_t type, uint64_t value);
    ~psyche_cmd_arg();

    psyche_cmd_arg& operator=(const psyche_cmd_arg& arg);
public:
    void set_size(uint8_t size);
    void set_type(uint32_t type);
    void set_value(uint64_t val);

public:
    uint8_t get_size() const;
    uint32_t get_type() const;
    uint64_t get_value() const;
};


class psyche_cmd {
    uint8_t size;
    uint32_t opcode;

    std::vector<psyche_cmd_arg> args;

    psyche_block * parent;

    psyche_handler* handler_entry;
    psyche_pcode* pcode_entry;

public:
    psyche_cmd();
    psyche_cmd(const psyche_cmd& command);
    psyche_cmd(uint8_t size, uint32_t opcode);
    psyche_cmd(uint8_t size, uint32_t opcode, const psyche_cmd_arg& arg_1);
    psyche_cmd(uint8_t size, uint32_t opcode, const psyche_cmd_arg& arg_1, const psyche_cmd_arg& arg_2);
    psyche_cmd(uint8_t size, uint32_t opcode, const psyche_cmd_arg& arg_1, const psyche_cmd_arg& arg_2, const psyche_cmd_arg& arg_3);
    ~psyche_cmd();

    psyche_cmd& operator=(const psyche_cmd& command);
public:
    void set_size(uint8_t size);
    void set_opcode(uint32_t op);
    void set_args(const std::vector<psyche_cmd_arg>& args);
    void set_parent(psyche_block * parent);

    void set_handler_entry(psyche_handler* handler_entry);
    void set_pcode_entry(psyche_pcode* pcode_entry);

public:
    uint8_t get_size() const;
    uint32_t get_opcode() const;
    
    const psyche_block* get_parent() const;
    psyche_block* get_parent();

    const psyche_handler* get_handler_entry() const;
    psyche_handler* get_handler_entry();

    const psyche_pcode* get_pcode_entry() const;
    psyche_pcode* get_pcode_entry();

    const std::vector<psyche_cmd_arg>& get_args() const;
    std::vector<psyche_cmd_arg>& get_args();
};





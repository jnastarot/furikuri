#pragma once
#include "..\distorm_lib\include\distorm.h"
#include "..\distorm_lib\include\mnemonics.h"

class fuku_obfuscator;
class fuku_instruction;
class fuku_mutation;

#include "fuku_instruction.h"
#include "fuku_mutation.h"
#include "fuku_obfuscator.h"
#include "fuku_asm.h"

#include "fuku_graph_spider.h"
#include "fuku_protector.h"

class furikuri
{
public:
    furikuri();
    ~furikuri();
};


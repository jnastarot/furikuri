#pragma once

#define WIN32_LEAN_AND_MEAN     

#include <vector>
#include <list>
#include <string>
#include <algorithm>
#include <map>
#include <set>
#include <time.h>
#include <stdio.h>
#include <sstream>
#include <iostream>
#include <iostream>
#include <stdarg.h> 
#include <cstdint>
#include <random>  
#include <intrin.h>

using namespace std;


#pragma comment(lib,"enma_pe.lib")
#pragma comment(lib,"shibari.lib")
#pragma comment(lib,"capstone.lib")
#pragma comment(lib,"fukutasm.lib")

#include "enma_pe\enma_pe\enma_pe.h"
#include "shibari\shibari\shibari.h"

#define FUKU_GET_RAND(_min,_max) ((_min) == (_max) ? (_min) : ((_min) + ( (rand() | rand() << 16) %(((_max) + (((_max) == UINT_MAX) ? 0 : 1)) - (_min)))))

#define FUKU_GET_CHANCE(x) (FUKU_GET_RAND(1,1000) <= (10*(x))) //0.f - 100.f in

#define GET_BITES(src, mask) ( (src) & (mask) )
#define HAS_FULL_MASK(src, mask) ( ( (src) & (mask) ) == (mask) )


#ifdef _DEBUG
#define FUKU_DEBUG {printf("%s:%d | %s\n",__FILE__,__LINE__,__FUNCTION__);}
#else
#define FUKU_DEBUG __nop();
#endif

#define FUKU_ASSERT(cond) if( !(cond)){FUKU_DEBUG}   
#define FUKU_ASSERT_EQ(lhs, rhs) if( !((lhs) == (rhs)) ){FUKU_DEBUG}
#define FUKU_ASSERT_GT(lhs, rhs) if( !((lhs) >  (rhs)) ){FUKU_DEBUG}

#include "furikuri.h"
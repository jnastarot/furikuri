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

using namespace std;


#pragma comment(lib,"enma_pe.lib")
#pragma comment(lib,"shibari.lib")
#pragma comment(lib,"distorm_lib.lib")

#include "enma_pe\enma_pe\enma_pe.h"
#include "shibari\shibari\shibari.h"

#define FUKU_GET_RAND(_min,_max) ((_min) == (_max) ? (_min) : ((_min) + (rand()%(((_max) + (((_max) == UINT_MAX) ? 0 : 1)) - (_min)))))


#define FUKU_GET_CHANCE(x) (FUKU_GET_RAND(1,1000) <= (10*(x))) //0.f - 100.f in

#ifdef _DEBUG
    #define FUKU_DEBUG {printf("%s:%d | %s\n",__FILE__,__LINE__,__FUNCTION__);}
#else
    #define FUKU_DEBUG {}
#endif

#include "furikuri.h"
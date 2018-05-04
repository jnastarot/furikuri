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

using namespace std;


#ifndef _M_X64
  #ifdef _DEBUG
    #pragma comment(lib,"..\\Debug\\shibari.lib")
  #else
	#pragma comment(lib,"..\\Release\\shibari.lib")
  #endif
#else
  #ifdef _DEBUG
	#pragma comment(lib,"..\\x64\\Debug\\shibari.lib")
  #else
	#pragma comment(lib,"..\\x64\\Release\\shibari.lib")
  #endif
#endif

#include "..\shibari\shibari\shibari.h"
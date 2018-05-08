#pragma once

#include <stdio.h>
#include <tchar.h>


#ifndef _M_X64
  #ifdef _DEBUG
    #pragma comment(lib,"..\\Debug\\furikuri.lib")
  #else
	#pragma comment(lib,"..\\Release\\furikuri.lib")
  #endif
#else
  #ifdef _DEBUG
	#pragma comment(lib,"..\\x64\\Debug\\furikuri.lib")
  #else
	#pragma comment(lib,"..\\x64\\Release\\furikuri.lib")
  #endif
#endif

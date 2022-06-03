#ifndef _INCLUDES_H_
#define _INCLUDES_H_
#define no_init_all 

#include <windows.h>
#include <lm.h>

#include <iostream>
#include <NTSecAPI.h>

extern LSA_HANDLE policy;

LSA_HANDLE GetPolicyHandle();
bool InitLsaString(
    PLSA_UNICODE_STRING pLsaString,
    LPCWSTR pwszString
);

#endif
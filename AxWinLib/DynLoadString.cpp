#include "StdAfx.h"

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

// Windows Header Files:
#include <windows.h>
#include <tchar.h>

// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>

/// \brief Support routine. Get an allocated string from a resource string table.
///
/// Get a string from a string table, but ensure that
/// that it's in a dynamically allocated buffer of sufficient
/// size. I see no real alterantive to the cut and try method
/// below. Aargh.
/// \param uId The string resource ID
/// \param hModule The module handle to use. Default is NULL to use the calling exe
/// \return An allocated string or NULL on error. Do remember to free.
_TCHAR *
DynLoadString(UINT uId, HMODULE hModule = NULL) {
    if (!hModule) hModule = GetModuleHandle(NULL); // Default to calling exe
    size_t cbString = 0;
    _TCHAR *szString = NULL;
    DWORD dwLen;
    do {
        _TCHAR *t = (_TCHAR *)realloc(szString, (cbString += 50) * sizeof _TCHAR);
        if (!t) {
            free(szString);
            return NULL;
        }
        szString = t;
        dwLen = LoadString(hModule, uId, szString, (int)cbString);
        if (!dwLen) {
            free(szString);
            return NULL;
        }
    } while (dwLen >= (cbString - 1));
    return szString;
}

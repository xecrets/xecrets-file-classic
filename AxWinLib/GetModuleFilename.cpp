#include "StdAfx.h"

#define WIN32_LEAN_AND_MEAN		            ///< Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <tchar.h>

#include <stdlib.h>

/// \brief Get an allocated buffer with the fully qualified name of a module
///  Get the fully qualified name of a module, but ensure that
///  that it's in a dynamically allocated buffer of sufficient
///  size. I see no real alterantive to the cut and try method
///  below. Aargh.
/// \param hModule The module handle or NULL for the current program
/// \return An allocated buffer that needs to be free()'d. It may be NULL on error.
_TCHAR *MyGetModuleFileName(HMODULE hModule) {
    size_t cbFileName = 0;
    _TCHAR *szFileName = NULL;
    size_t cbLen;
    do {
        _TCHAR *t = (_TCHAR *)realloc(szFileName, (cbFileName += MAX_PATH) * sizeof _TCHAR);
        if (!t) {
            free(szFileName);
            return NULL;
        }
        szFileName = t;
        cbLen = GetModuleFileName(hModule, szFileName, (DWORD)cbFileName);
        if (!cbLen) {
            free(szFileName);
            return NULL;
        }
    } while (cbLen >= (cbFileName - 1));
    return szFileName;
}
// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//
// This is a Windows-specific include - Generic definitions should not be here
//

#ifndef __STDAFX_H__
#define __STDAFX_H__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef WINVER
#define WINVER 0x0501           // Allow use of features specific to Windows XP, Windows Server 2003 or later.
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501     // Allow use of features specific to Windows XP, Windows Server 2003 or later.
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0550        // Specifies that the minimum required platform is Internet Explorer 5.5.
#endif

#define _RICHEDIT_VER	0x0100
//#define _SECURE_ATL 1
#define _CRT_RAND_S

#include <windows.h>
#include <shlobj.h>
#include <shlguid.h>
//#include <objbase.h>
#include <comdef.h>
#include <memory.h>

//
#define CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include <atlbase.h>
#include "atlapp.h"
#include <atlwin.h>
#include "atlframe.h"      // WTL frame window classes
#include "atlsplit.h"
#include "atlmisc.h"      // WTL utility classes like CString
#include "atlctrls.h"
#include "atlctrlw.h"
#include "atlctrlx.h"
#include "atlcrack.h"      // WTL enhanced msg map 
#include "atlddx.h"
#include "atldlgs.h"

#include <map>

#include "Axgettext.h"
#include "CConfigWin.h"

// Gettext definitions
// This should probably be fetched from a string resource instead for OEM-purposes in the future
#define GETTEXT_PACKAGE "AxCrypt2Go"
#define _(String) AxLib::CGettext::Gettext (String)
#define N_(String) String

enum {
    MENU_DUMMY,
    MENU_FILE_OPEN,
    MENU_FILE_ENCRYPT,
    MENU_FILE_DECRYPT,
    MENU_FILE_EXIT,
    MENU_VIEW_LARGEICONS,
    MENU_VIEW_SMALLICONS,
    MENU_VIEW_LIST,
    MENU_VIEW_DETAILS,
    MENU_VIEW_REFRESH,
    MENU_HELP_ABOUT,
};

extern const _TCHAR *GetComMsg(HRESULT hr);
#ifndef ASSCOM
/// \brief Assert the HRESULT from a COM operation
/// }param hResult A HRESULT from a COM operation
#define ASSCOM(hResult) if (FAILED(hResult)) AxLib::AssFunc(false, GetComMsg(hResult), _T(AXLIB_ASSERT_FILE), __LINE__)
#endif

#endif //__STDAFX_H__

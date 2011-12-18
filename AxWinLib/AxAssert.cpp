/*! \file
    \brief Fatal assertions and formatted message box etc

    @(#) $Id$

    AxLib - Collection of useful code. All code here is generally intended to be simply included in
    the projects, the intention is not to províde a stand-alone linkable library, since so many
    variants are possible (single/multithread release/debug etc) and also because it is frequently
    used in open source programs, and then the distributed source must be complete and there is no
    real reason to make the distributions so large etc.

    It's of course also possible to build a partial or full library in the respective solution.

	Copyright (C) 2004 Svante Seleborg/Axantum Software AB, All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:axcrypt@axondata.se and http://axcrypt.sourceforge.net
----
	AxAssert.cpp
*/

#include "StdAfx.h"
#define WIN32_LEAN_AND_MEAN		            ///< Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <Shlwapi.h>

#include <memory>

// This should be done for every source file to ensure correct reference in the assert
#include "AxAssert.h"
#define AXLIB_ASSERT_FILE "AxAssert.cpp"

namespace AxLib {
/// \brief Get a string representation of a COM error
extern const _TCHAR *GetComMsg(HRESULT hr);

// Since this is only intended to be called for fatal failed asserts, including
// memory allocation, we preallocate a fixed size buffer here.
static _TCHAR szMsg[1024];

/// \brief Return a static buffer with the fully qualified name of a module
///  Get the fully qualified name of a module, and do it in statically
///  allocated buffer, since this is in an assert-situation - there may be
///  no memmory to allocate for example.
/// \param hModule The module handle or NULL for the current program
/// \return A static buffer with the name.
static _TCHAR *
MyGetModuleFileName(HMODULE hModule) {
	static _TCHAR szFileName[MAX_PATH];		// Will have to do.
	// Get the module file name. We accept a truncated return, but not an error.
	if (!GetModuleFileName(hModule, szFileName, sizeof szFileName)) {
		return _T("Unknown module. GetModuleFileName() failed too.");
	}
    return szFileName;
}

/// Get the 'raw' message definition from the system, based on LastError.
/// \return a pointer to a static buffer (and shut off warning about same).
#pragma warning(disable:4172)
const _TCHAR *
AxLib::LastErrorMsg() {
    (void)lstrcpy(szMsg, _T("Invalid GetLastError()"));
    DWORD dwLastError = GetLastError();
    if (FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_MAX_WIDTH_MASK,
        NULL, dwLastError, 0, szMsg, sizeof szMsg / sizeof szMsg[0], NULL) == 0) {
            (void)wsprintf(szMsg, _T("Error Code %d."), dwLastError);
            return szMsg;
    }

    // Overambitious perhaps, but remove trailing space that appears sometimes.
    _TCHAR *s = &szMsg[lstrlen(szMsg)];
    while (s-- != szMsg) {
        if (s[0] == ' ') {
            s[0] = _T('\0');
        } else {
            break;
        }
    }

    return szMsg;
}
#pragma warning(default:4172)

/// Get a string representation of the most recent system error
/// in an allocated string, possibly preceeded by the given argument.
/// \param sz A (optional) parameter used like sprintf(res, "%s: %s", sz, perror())
/// \return An allocated string, must be delete[]'d
_TCHAR *
AxLib::APerror(const _TCHAR *sz) {
    // wsprintf has a built-in limit of 1024
    _TCHAR *szRes = new _TCHAR[1024];
    ASSPTR(szRes);
    if (sz) {
        (void)wsprintf(szRes, _T("%s: %s"), sz, LastErrorMsg());
    } else {
        (void)lstrcpyn(szRes, LastErrorMsg(), 1024);
    }
    return szRes;
}

/// If the an assertion fails, format and display a message instead before exiting.
/// \param fOk The assertion, if true nothing happens.
/// \param sz The message to display.
/// \param szFile The module name where the assertion is done.
/// \param iLine The line number in the module where the assertion is done.
void
AxLib::AssFunc(bool fOk, const _TCHAR *sz, const _TCHAR *szFile, int iLine) {
    // Get hold of the executable name and use that as assertion title.
	// This works because the buffer returned is static
	_TCHAR *szProg = PathFindFileName(MyGetModuleFileName(NULL));
    if (!fOk) {
        MessageBoxF(_T("Failed assertion in %s at line %d\n\n%s"), szProg,  MB_OK|MB_ICONSTOP, PathFindFileName(szFile), iLine, sz);
        exit(1);
    }
}

/// MessageBox() with printf() functionality
/// \param szFmt a printf() format string
/// \param szCaption the message box caption
/// \param uType The message box type, i.e. MB_OK etc
void
AxLib::MessageBoxF(const _TCHAR *szFmt, const _TCHAR *szCaption, unsigned int uType, ...) {
    va_list vaArgs;
    va_start(vaArgs, uType);

    // wvsprintf guarantees not to write more than 1024 chars
    static _TCHAR szBuf[1024];
    wvsprintf(szBuf, szFmt, vaArgs);
    va_end(vaArgs);
    MessageBox(NULL, szBuf, szCaption, uType);
}

#ifdef _DEBUG
/// OutputDebugString with printf() functionality. The result must not
/// be more that 1024 characters long, or it will be truncated.
/// \param szFmt A printf format string.
void
AxLib::OutputDebugStringF(const _TCHAR *szFmt, ...) {
    va_list vaArgs;
    va_start(vaArgs, szFmt);

    // wvsprintf guarantees not to write more than 1024 chars
    static _TCHAR szBuf[1024];
    wvsprintf(szBuf, szFmt, vaArgs);
    va_end(vaArgs);
    OutputDebugString(szBuf);
}
#endif

} // namespace AxLib

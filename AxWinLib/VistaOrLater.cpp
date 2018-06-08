/*! \file
    \brief Support routines for Vista or later

    @(#) $Id$

    Various things that are special for Vista or later

    Copyright (C) 2006 Svante Seleborg/Axantum Software AB, All rights reserved.

    This program is free software; you can redistribute it and/or modify it under the terms
    of the GNU General Public License as published by the Free Software Foundation;
    either version 2 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program;
    if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
    Boston, MA 02111-1307 USA

    The author may be reached at mailto:svante@axantum.com and http://wwww.axantum.com
----
    VistaOrLater.cpp
*/
#include "stdafx.h"

#ifndef WINVER
#define WINVER 0x0600           // Allow use of features specific to Windows Vista or later.
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600     // Allow use of features specific to Windows Vista or later.
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0600        // Specifies that the minimum required platform is Internet Explorer 6.0.
#endif

#include <windows.h>
#include <tchar.h>
#include <shellapi.h>

#include <memory>
#include <VersionHelpers.h>

#include "VistaOrLater.h"
#include "GetModuleFilename.h"

    /// \brief Determine if we're running Vista or later
    /// \return true if we're running Vista or later
bool awl::IsVistaOrLater() {
	return IsWindowsVistaOrGreater();
}

bool awl::NeedsAndCanElevateOnVista() {
    if (!awl::IsVistaOrLater()) {
        return false;
    }

	HANDLE hToken = NULL;
	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
	}

    TOKEN_ELEVATION_TYPE tet = (TOKEN_ELEVATION_TYPE)0;

	DWORD dwReturnLength = 0;
    if (!::GetTokenInformation(hToken, TokenElevationType, &tet, sizeof tet, &dwReturnLength)) {
        ::CloseHandle(hToken);
		return false;
	}
	::CloseHandle(hToken);

    if (dwReturnLength != sizeof tet) {
        return false;
    }

    // TokenElevationTypeDefault => Process doesn't have a split token, so no elevation is possible.
    // TokenElevationTypeFull => The process is already elevated.
    return tet == TokenElevationTypeLimited;
}

///< Are we running as admin one way or another on Vista?
bool awl::IsAdminOnVista() {
    if (!awl::IsVistaOrLater()) {
        return false;
    }

	HANDLE hToken = NULL;
	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
	}

    TOKEN_ELEVATION te = { 0 };
    DWORD dwReturnLength = 0;
    if (!::GetTokenInformation(hToken, TokenElevation, &te, sizeof te, &dwReturnLength)) {
        ::CloseHandle(hToken);
        return false;
    }
    ::CloseHandle(hToken);

    if (dwReturnLength != sizeof te) {
        return false;
    }

    return te.TokenIsElevated != 0;
}

/// \brief Actually elevate on Vista
/// \return true if we at least tried to relaunch, false if we did not (and the caller should proceed to actually do the work).
bool awl::RelaunchElevatedOnVista(DWORD *pdwReturnCode, HWND hWnd, int nShowCmd) {
    if (!awl::IsVistaOrLater()) {
        return false;
    }

    if (!awl::NeedsAndCanElevateOnVista() || awl::IsAdminOnVista()) {
        return false;
    }

    *pdwReturnCode = -1;
    std::auto_ptr<TCHAR> moduleFileName(MyGetModuleFileName(NULL));

    TCHAR *pArgs = GetCommandLine();
    if (pArgs[0] == _T('"')) {
        ++pArgs;
        // This will work - the path can't end with \", regardless of circumstances as far as we know
        while (pArgs[0] && (pArgs[0] != _T('"') || pArgs[-1] == _T('\\'))) {
            ++pArgs;
        }
        ++pArgs; // Skip the " as well.
    } else {
        while (pArgs[0] && pArgs[0] != _T(' ')) {
            ++pArgs;
        }
    }
    // Skip to start of arguments.
    while (pArgs[0] && pArgs[0] == _T(' ')) {
        ++pArgs;
    }

    SHELLEXECUTEINFO shex = { 0 };
    shex.cbSize = sizeof shex;

    shex.fMask = SEE_MASK_NOCLOSEPROCESS;
    shex.hwnd = hWnd;
    shex.lpVerb = _T("runas");
    shex.nShow = nShowCmd;
    shex.lpFile = moduleFileName.get();
    shex.lpParameters = pArgs;

    if (ShellExecuteEx(&shex)) {
        if (shex.hProcess != NULL && shex.hProcess != INVALID_HANDLE_VALUE) {
            if (WaitForSingleObject(shex.hProcess, INFINITE) == WAIT_OBJECT_0) {
                GetExitCodeProcess(shex.hProcess, pdwReturnCode);
            }
            ::CloseHandle(shex.hProcess);
        }
    }

    // We have at least attempted to launch
    return true;
}

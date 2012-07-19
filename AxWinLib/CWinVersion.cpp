/*! \file
\brief Determine Windows Version

@(#) $Id$

AxLib - Collection of useful code. All code here is generally intended to be simply included in
the projects, the intention is not to províde a stand-alone linkable library, since so many
variants are possible (single/multithread release/debug etc) and also because it is frequently
used in open source programs, and then the distributed source must be complete and there is no
real reason to make the distributions so large etc.

It's of course also possible to build a partial or full library in the respective solution.

Copyright (C) 2009 Svante Seleborg/Axantum Software AB, All rights reserved.

This program is free software; you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation;
either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program;
if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
Boston, MA 02111-1307 USA

The author may be reached at mailto:software@axantum.com and http://www.axantum.com
----
AxAssert.cpp
*/

#include "StdAfx.h"
#define WIN32_LEAN_AND_MEAN		            ///< Exclude rarely-used stuff from Windows headers
#include <windows.h>

#include "IWinVersion.h"

// This should be done for every source file to ensure correct reference in the assert
#include "AxAssert.h"
#define AXLIB_ASSERT_FILE "CWinVersion.cpp"

namespace AxLib {
    class CWinVersion : public IWinVersion {
        int GetVersion();
    };

    IWinVersion::~IWinVersion() {
    }

    IWinVersion *IWinVersion::New() {
        return new CWinVersion();
    }

    int CWinVersion::GetVersion() {
        OSVERSIONINFOEX osvix;

        ZeroMemory(&osvix, sizeof osvix);
        osvix.dwOSVersionInfoSize = sizeof osvix;
        ASSAPI(GetVersionEx((LPOSVERSIONINFO)&osvix));

        SYSTEM_INFO si;
        ZeroMemory(&si, sizeof si);
        typedef void (WINAPI *PFGETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

        HMODULE hKernel32;
        PFGETNATIVESYSTEMINFO pfGetNativeSystemInfo;
        if (hKernel32 = GetModuleHandle(_T("kernel32.dll"))) {
            pfGetNativeSystemInfo = (PFGETNATIVESYSTEMINFO)GetProcAddress(hKernel32, "GetNativeSystemInfo");
        }
        if (pfGetNativeSystemInfo != NULL) {
            (*pfGetNativeSystemInfo)(&si);
        } else {
            GetSystemInfo(&si);
        }

        int version = WINXX;

        // See http://msdn.microsoft.com/en-us/library/ms724833(VS.85).aspx for background info
        switch (osvix.dwMajorVersion) {
            case 6:
                switch (osvix.dwMinorVersion) {
                    case 1:
                        if (osvix.wProductType == VER_NT_WORKSTATION) {
                            version = WIN7;
                        } else {
                            version = WIN2008;
                        }
                        break;
                    case 0:
                        if (osvix.wProductType != VER_NT_WORKSTATION) {
                            version = WIN2008;
                        } else {
                            version = WINVISTA;
                        }
                        break;
                    default:
                        version = WINXX;
                        break;
                }
                break;
            case 5:
                switch (osvix.dwMinorVersion) {
                    case 2:
// WH is not relevant, nor defined for 64-bit system
#ifdef VER_SUITE_WH_SERVER
                        if (osvix.wSuiteMask == VER_SUITE_WH_SERVER) {
                            version = WINHS;
                        } else
#endif
                        if (osvix.wProductType == VER_NT_WORKSTATION && si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
                            version = WINXP | X64;
                        } else if (GetSystemMetrics(SM_SERVERR2) != 0) {
                            version = W2003; // R2
                        } else {
                            version = W2003;
                        }
                        break;
                    case 1:
                        version = WINXP;
                        break;
                    case 0:
                        version = WIN2K;
                        break;
                    default:
                        version = WINXX;
                        break;
                }
                break;
            default:
                version = WINXX;
                break;
        }
        // If we have not already determined bitness, let's check the system info
        if ((version & X64) != X64) {
            if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
                version |= X64;
            }
        }

        return version;
    }
}
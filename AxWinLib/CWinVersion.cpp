/*! \file
\brief Determine Windows Version

@(#) $Id$

AxLib - Collection of useful code. All code here is generally intended to be simply included in
the projects, the intention is not to províde a stand-alone linkable library, since so many
variants are possible (single/multithread release/debug etc) and also because it is frequently
used in open source programs, and then the distributed source must be complete and there is no
real reason to make the distributions so large etc.

It's of course also possible to build a partial or full library in the respective solution.

Copyright (C) 2009-2022 Svante Seleborg/Axantum Software AB, All rights reserved.

This program is free software; you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation;
either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program;
if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
Boston, MA 02111-1307 USA

The author may be reached at mailto:support@axantum.com and http://www.axantum.com
----
AxAssert.cpp
*/

#include "StdAfx.h"
#define WIN32_LEAN_AND_MEAN		            ///< Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <VersionHelpers.h>
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

	IWinVersion* IWinVersion::New() {
		return new CWinVersion();
	}

	int CWinVersion::GetVersion() {
		// See https://msdn.microsoft.com/en-us/library/windows/desktop/dn424972(v=vs.85).aspx
		int version;
		if (IsWindows8OrGreater()) {
			version = WINXX;
		}
		else if (IsWindows7OrGreater()) {
			version = IsWindowsServer() ? WIN2008 : WIN7;
		}
		else if (IsWindowsVistaOrGreater()) {
			version = IsWindowsServer() ? WIN2008 : WINVISTA;
		}
		else {
			version = WINXX;
		}

		typedef void (WINAPI* PFGETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);
		HMODULE hKernel32;
		PFGETNATIVESYSTEMINFO pfGetNativeSystemInfo;

		if (hKernel32 = GetModuleHandle(_T("kernel32.dll"))) {
			pfGetNativeSystemInfo = (PFGETNATIVESYSTEMINFO)GetProcAddress(hKernel32, "GetNativeSystemInfo");
		}

		SYSTEM_INFO si;
		ZeroMemory(&si, sizeof si);

		if (pfGetNativeSystemInfo != NULL) {
			(*pfGetNativeSystemInfo)(&si);
		}
		else {
			GetSystemInfo(&si);
		}

		if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
			version |= X64;
		}

		return version;
	}
}
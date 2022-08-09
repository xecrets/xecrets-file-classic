/*! \file
	\brief Get various version info from version resources of an exectuable

	@(#) $Id$

	AxLib - Collection of useful code. All code here is generally intended to be simply included in
	the projects, the intention is not to províde a stand-alone linkable library, since so many
	variants are possible (single/multithread release/debug etc) and also because it is frequently
	used in open source programs, and then the distributed source must be complete and there is no
	real reason to make the distributions so large etc.

	It's of course also possible to build a partial or full library in the respective solution.

	Copyright (C) 2006-2022 Svante Seleborg/Axantum Software AB, All rights reserved.

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
	CVersionWin.cpp
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

#define WIN32_LEAN_AND_MEAN		            ///< Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <tchar.h>

#include "CVersionWin.h"

#include "AxAssert.h"
#define AXLIB_ASSERT_FILE "CVersionWin.cpp"

namespace AxLib {
	/// \brief Support routine. Get an allocated string from a resource string table.
	///
	/// Get a string from a string table, but ensure that
	/// that it's in a dynamically allocated buffer of sufficient
	/// size. I see no real alterantive to the cut and try method
	/// below. Aargh.
	/// \param uId The string resource ID
	/// \param hModule The module handle to use. Default is NULL to use the calling exe
	/// \return An new[]'d string or NULL on error. Do remember to delete[].
	_TCHAR*
		CVersion::newLoadString(UINT uId, HMODULE hModule) {
		if (!hModule) hModule = GetModuleHandle(NULL); // Default to calling exe
		size_t ccString = 0;
		_TCHAR* szString = NULL;
		DWORD dwLen;
		do {
			_TCHAR* t = new _TCHAR[ccString += 50];
			ASSPTR(t);
			if (szString != NULL) {
				_tcsncpy_s(t, ccString, szString, ccString - 50);
				delete[] szString;
			}
			szString = t;
			dwLen = LoadString(hModule, uId, szString, (int)ccString);
			if (!dwLen) {
				delete[] szString;
				return NULL;
			}
		} while (dwLen >= (ccString - 1));
		return szString;
	}

	/// \brief Initalize and load the actual version resources
	///
	/// Get the version resources
	/// from an executable. Will assert and exit on error.
	/// \param hInstance The module with the resources. NULL means ourselves.
	CVersion::CVersion(HINSTANCE hInstance) {
		m_pFileVersionInfo = NULL;

		// Get the version resource from the executable identified by the instance
		_TCHAR szFileName[MAX_PATH];
		ASSAPI(GetModuleFileName(hInstance, szFileName, sizeof szFileName) != 0);

		DWORD dwDummy, dwLen = GetFileVersionInfoSize(szFileName, &dwDummy);
		ASSAPI(dwLen != 0);
		m_pFileVersionInfo = new BYTE[dwLen];
		ASSPTR(m_pFileVersionInfo);

		ASSAPI(GetFileVersionInfo(szFileName, dwDummy, dwLen, m_pFileVersionInfo) == TRUE);
		UINT uLen = 0;
		ASSAPI(VerQueryValue(m_pFileVersionInfo, _T("\\"), (void**)&m_pFixedFileInfo, &uLen) == TRUE);
	}

	/// \brief Clean up and free memory.
	CVersion::~CVersion() {
		delete[] m_pFileVersionInfo;
	}

	/// \brief Get the Major word of the version number, i.e. X.n.n.n
	/// \return A number 0-65536
	WORD
		CVersion::Major() {
		return (WORD)(m_pFixedFileInfo->dwProductVersionMS >> 16);
	}

	/// \brief Get the Minor word of the version number, i.e. n.X.n.n
	/// \return A number 0-65536
	WORD
		CVersion::Minor() {
		return (WORD)(m_pFixedFileInfo->dwProductVersionMS);
	}

	/// \brief Get the Minuscle word of the version number, n.n.X.n
	/// \return A number 0-65536
	WORD
		CVersion::Minuscle() {
		return (WORD)(m_pFixedFileInfo->dwProductVersionLS >> 16);
	}

	/// \brief Get the Patch level word of the version number, i.e. n.n.n.X
	/// \return A number 0-255
	WORD
		CVersion::Patch() {
		return (WORD)(m_pFixedFileInfo->dwProductVersionLS);
	}

	/// \brief Get the Product Name, taken from the resouces.
	/// \return An allocated string, must be delete'd.
	_TCHAR*
		CVersion::newProductName() {
		UINT uLen = 0;
		_TCHAR* szProductName = NULL;
		ASSAPI(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\ProductName"), (void**)&szProductName, &uLen) == TRUE);
		ASSCHK(szProductName && uLen != 0, _T(""));

		return lstrcpyn(new _TCHAR[uLen], szProductName, uLen);
	}

	/// \brief Get the Company name from the resources.
	/// \return An allocated string, must be delete[]'d.
	_TCHAR*
		CVersion::newCompanyName() {
		UINT uLen = 0;
		_TCHAR* szCompanyName = NULL;
		ASSAPI(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\CompanyName"), (void**)&szCompanyName, &uLen) == TRUE);
		ASSCHK(szCompanyName && uLen != 0, _T(""));

		return lstrcpyn(new _TCHAR[uLen], szCompanyName, uLen);
	}

	/// \brief Copyright string, from resource.
	/// \return An allocated string, must be delete[]'d.
	_TCHAR*
		CVersion::newLegalCopyright() {
		UINT uLen = 0;
		_TCHAR* szLegalCopyright = NULL;
		ASSAPI(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\LegalCopyright"), (void**)&szLegalCopyright, &uLen) == TRUE);
		ASSCHK(szLegalCopyright && uLen != 0, _T(""));

		return lstrcpyn(new _TCHAR[uLen], szLegalCopyright, uLen);
	}

	/// \brief Format a version string, including the product name, and possible a special build insert.
	/// \param szAltProductName Alternate product to use instead of resource-embedded.
	/// \return An allocated string, must be delete[]'d.
	_TCHAR*
		CVersion::newNameVersionString(UINT uProductName) {
		// Get special build field
		UINT uLen = 0;
		LPCTSTR szSpecialBuild = _T("");
		// It's not actually an error not to find this resource, VC7 doesn't included it if it's empty...
		VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\SpecialBuild"), (void**)&szSpecialBuild, &uLen);

		_TCHAR* szProductName;
		if (uProductName != 0) {
			szProductName = newLoadString(uProductName);
		}
		else {
			szProductName = newProductName();
		}
		_TCHAR* szVersionString = new _TCHAR[1024];
		if (szSpecialBuild && uLen) {
			wsprintf(szVersionString, Patch() ? _T("%s %d.%d.%d.%d %s") : _T("%s %d.%d.%d.%d %s"), szProductName, Major(), Minor(), Minuscle(), Patch(), szSpecialBuild);
		}
		else {
			wsprintf(szVersionString, Patch() ? _T("%s %d.%d.%d.%d") : _T("%s %d.%d.%d.%d"), szProductName, Major(), Minor(), Minuscle(), Patch());
		}
		delete szProductName;

		return szVersionString;
	}
} // namespace AxLib
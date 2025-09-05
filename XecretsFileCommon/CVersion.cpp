/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
	CVersion.cpp					Get and present version information

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001-12-06				Initial
*/
#include	"StdAfx.h"
#include	"stdio.h"
#include    <iostream>
#include    <sstream>
#include	"CVersion.h"
#include    "CRegistry.h"
#include    "CFileName.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CVersion.cpp"

HINSTANCE CVersion::m_hInstance;

void CVersion::Init(HINSTANCE hInstance) {
	m_hInstance = hInstance;
}

CVersion::CVersion(HINSTANCE hInstance) {
	_TCHAR szFileName[_MAX_PATH];
	CAssert(GetModuleFileName(hInstance == NULL ? m_hInstance : hInstance, szFileName, sizeof szFileName)).Sys().Throw();
	Init(szFileName);
}

CVersion::CVersion(const _TCHAR* szFileName) {
	Init(szFileName);
}

CVersion::~CVersion() {
	if (m_pFileVersionInfo != NULL) {
		delete[] m_pFileVersionInfo;
	}
}

void CVersion::Init(const _TCHAR* szFileName) {
	m_szExtProductName = NULL;
	m_szCompanyName = NULL;
	m_szLegalCopyright = NULL;
	m_szFileDescription = NULL;

	// This will be a memory leak unless we note this here.
	HEAP_CHECK_BEGIN(_T("CVersion::CVersion()"), TRUE)

		DWORD dwDummy, dwLen = GetFileVersionInfoSize(szFileName, &dwDummy);
	CAssert(dwLen != 0).Sys().Throw();

	m_pFileVersionInfo = new BYTE[dwLen];
	if (m_pFileVersionInfo == NULL) {
		ASSPTR(m_pFileVersionInfo);
	}

	CAssert(GetFileVersionInfo(szFileName, dwDummy, dwLen, m_pFileVersionInfo));
	HEAP_CHECK_END
		UINT uLen = 0;
	CAssert(VerQueryValue(m_pFileVersionInfo, _T("\\"), (void**)&m_pFixedFileInfo, &uLen)).Sys().Throw();
}

WORD
CVersion::FileMajor() {
	return oFileMajor;
}

WORD
CVersion::FileMinor() {
	return oFileMinor;
}

WORD
CVersion::Major() {
	return (WORD)(m_pFixedFileInfo->dwProductVersionMS >> 16);
}

WORD
CVersion::Minor() {
	return (WORD)(m_pFixedFileInfo->dwProductVersionMS);
}

WORD
CVersion::Minuscle() {
	return (WORD)(m_pFixedFileInfo->dwProductVersionLS >> 16);
}

WORD
CVersion::Patch() {
	return (WORD)(m_pFixedFileInfo->dwProductVersionLS);
}

WORD
CVersion::MajorFileVersion() {
	return (WORD)(m_pFixedFileInfo->dwFileVersionMS >> 16);
}

WORD
CVersion::MinorFileVersion() {
	return (WORD)(m_pFixedFileInfo->dwFileVersionMS);
}

WORD
CVersion::MinuscleFileVersion() {
	return (WORD)(m_pFixedFileInfo->dwFileVersionLS >> 16);
}

WORD
CVersion::PatchFileVersion() {
	return (WORD)(m_pFixedFileInfo->dwFileVersionLS);
}
//
//
//
LPCTSTR
CVersion::ExtProductName() {
	if (m_szExtProductName == NULL) {
		UINT uLen = 0;

		LPTSTR szProductName = NULL;
		CAssert(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\ProductName"), (void**)&szProductName, &uLen)).App(ERR_VERSION_RESOURCE).Throw();

		m_szExtProductName = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValProductName).GetSz(szProductName);
	}
	return m_szExtProductName;
}
//
//  _tcslwr the result...
//
LPCTSTR
CVersion::IntProductName() {
	if (m_szIntProductName == NULL) {
		m_szIntProductName = CopySz(CFileName().SetPath2ExeName(ghInstance).GetName());
	}
	return m_szIntProductName;
}
//
// Company name, from resource.
//
LPCTSTR CVersion::CompanyName() {
	if (m_szCompanyName == NULL) {
		UINT uLen = 0;

		CAssert(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\CompanyName"), (void**)&m_szCompanyName, &uLen)).App(ERR_VERSION_RESOURCE).Throw();
	}
	return m_szCompanyName;
}
//
// Copyright string, from resource.
//
LPCTSTR CVersion::LegalCopyright() {
	if (m_szLegalCopyright == NULL) {
		UINT uLen = 0;

		CAssert(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\LegalCopyright"), (void**)&m_szLegalCopyright, &uLen)).App(ERR_VERSION_RESOURCE).Throw();
	}
	return m_szLegalCopyright;
}

//
// FileDescription string, from resource.
//
LPCTSTR CVersion::FileDescription() {
	if (m_szFileDescription == NULL) {
		UINT uLen = 0;

		CAssert(VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\FileDescription"), (void**)&m_szFileDescription, &uLen)).App(ERR_VERSION_RESOURCE).Throw();
	}
	return m_szFileDescription;
}

/// \brief Get a formatted version string for the file version from resources
/// \return An allocated string. Do delete afterwards.
const _TCHAR*
CVersion::FileVersionString() {
	_TCHAR* sz = new _TCHAR[1024];          // wsprintf guarantees <= 1024
	UINT uLen = 0;

	LPCTSTR szSpecialBuild = _T("");        // It's not necessarily an error with no SpecialBuild resource
	VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\SpecialBuild"), (void**)&szSpecialBuild, &uLen);

	// Keep the various cases here, but we're switching to the MS format of 1.7.1751.0 etc for typical version info.
	if (szSpecialBuild && uLen) {
		wsprintf(sz, PatchFileVersion() ? _T("%d.%d.%d.%d %s") : _T("%d.%d.%d.%d %s"), MajorFileVersion(), MinorFileVersion(), MinuscleFileVersion(), PatchFileVersion(), szSpecialBuild);
	}
	else {
		wsprintf(sz, PatchFileVersion() ? _T("%d.%d.%d.%d") : _T("%d.%d.%d.%d"), MajorFileVersion(), MinorFileVersion(), MinuscleFileVersion(), PatchFileVersion());
	}
	return sz;
}

/// \brief A fixed-format version string with all 4 elements and dot between.
wstring
CVersion::GenericVersionString() {
	wostringstream stm;
	stm << MajorFileVersion() << L'.' << MinorFileVersion() << L'.' << MinuscleFileVersion() << L'.' << PatchFileVersion();
	return stm.str();
}

LPCTSTR
CVersion::String(bool fShowNoVersion) {
	// If we're not showing version info...
	if (fShowNoVersion) {
		m_szString.Fmt(_T("%1"), gszAxCryptExternalName);
	}
	else {
		UINT uLen = 0;

		LPCTSTR szSpecialBuild = _T("");        // It's not necessarily an error with no SpecialBuild
		VerQueryValue(m_pFileVersionInfo, _T("\\StringFileInfo\\000004b0\\SpecialBuild"), (void**)&szSpecialBuild, &uLen);

		if (szSpecialBuild && uLen) {
			m_szString.Fmt(Patch() ? _T("%1 %2!d!.%3!d!.%5!d!.%6!d! %4") : _T("%1 %2!d!.%3!d!.%5!d!.%6!d! %4"), gszAxCryptExternalName, Major(), Minor(), szSpecialBuild, Minuscle(), Patch());
		}
		else {
			m_szString.Fmt(Patch() ? _T("%1 %2!d!.%3!d!.%4!d!.%5!d!") : _T("%1 %2!d!.%3!d!.%4!d!.%5!d!"), gszAxCryptExternalName, Major(), Minor(), Minuscle(), Patch());
		}
	}
	return m_szString.Get();
}
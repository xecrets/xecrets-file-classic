/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2022 Svante Seleborg/Axon Data, All rights reserved.

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
	CFileName.cpp					File name related utility operations.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial
									2002-08-11              Rel 1.2

*/
#include	"StdAfx.h"
#include    "shlwapi.h"

#include	"CFileName.h"
#include	"CVersion.h"
//#ifndef	_SHELLEXTENSION
//#include	"CCryptoRand.h"
//#endif
#include	"Utility.h"
#include	"stdio.h"
//#include    "CFile.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CFileName.cpp"

CFileName::CFileName() {
	Split(_T(""));
}

CFileName::CFileName(LPCTSTR szFileName) {
	Split(szFileName);
}

CFileName&
CFileName::SetPath2ExeName(HINSTANCE hInstance) {
	CAssert(GetModuleFileName(hInstance, m_szWorkName, sizeof m_szWorkName / sizeof TCHAR) != 0).Sys().Throw();
	Split(m_szWorkName);
	return *this;
}

CFileName&
CFileName::SetPath2TempDir() {
	// Be Terminal Services / Fast User Switching aware here
	typedef BOOL(WINAPI* pfProcessIdToSessionIdT)(DWORD dwProcessId, DWORD* pSessionId);
	pfProcessIdToSessionIdT pfProcessIdToSessionId = (pfProcessIdToSessionIdT)GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "ProcessIdToSessionId");
	TCHAR* szSubDir = gszAxCryptInternalName, sz[1024];
	DWORD  dw = 0;
	if (pfProcessIdToSessionId != NULL) {
		// Terminal Services appear to exist in this environment
		pfProcessIdToSessionId(GetCurrentProcessId(), &dw);
	}
	// If the session ID is non-zero only do we modify the default name
	if (dw != 0) {
		wsprintf(sz, _TT("%s%d"), gszAxCryptInternalName, dw);
		szSubDir = sz;
	}

	SetPath2SysTempDir();

	SetDir(CStrPtr(GetDir()) + /*CStrPtr(_T("\\")) +*/ CStrPtr(szSubDir) + CStrPtr(_T("\\")));
	if (!CreateDirectory(GetDir(), NULL)) {
		CAssert(GetLastError() == ERROR_ALREADY_EXISTS).Sys().Throw();
	}

	return *this;
}
//
//  Set the path to just the system temp directory.
//
CFileName&
CFileName::SetPath2SysTempDir() {
	// The user may set unexpected values to TMP for example, including just a drive-
	// letter such as Z:, or a root directory such as Z:\. This complicates matters,
	// and it appears
	DWORD dwTempPathLen = GetTempPath(0, NULL);
	CStrPtr szTempPath(dwTempPathLen);
	// The length returned is sometimes not exact - just sufficient, so check for non-overflow not exactness.
	CAssert(GetTempPath(dwTempPathLen, szTempPath) < dwTempPathLen).Sys(MSG_SYSTEM_CALL, _T("GetTempPath() [CFileIO::MakeTemp()]")).Throw();

	SetDir(szTempPath);

	// If we by some chance do not get a directory, let's use the root folder.
	if (!m_szDir[0]) {
		SetDir(GetRootDir());
	}

	// Not all os's guarantees the existance of the directory... But do not try to
	// create the root dir - that's guaranteed to exist!
	if ((_tcscmp(m_szDir, _T("\\")) != 0) && (!CreateDirectory(GetDir(), NULL))) {
		CAssert((GetLastError() == ERROR_ALREADY_EXISTS) || (GetLastError() == ERROR_FILE_EXISTS)).Sys().Throw();
	}
	return *this;
}
//
//	Set name only
//
CFileName&
CFileName::SetName(LPCTSTR szFileName) {
	_tsplitpath_s(szFileName, NULL, 0, NULL, 0, m_szName, sizeof m_szName / sizeof m_szName[0], NULL, 0);
	return *this;
}
//
//	Set extension only
//
CFileName&
CFileName::SetExt(LPCTSTR szExt) {
	_tsplitpath_s(szExt, NULL, 0, NULL, 0, NULL, 0, m_szExt, sizeof m_szExt / sizeof m_szExt[0]);
	return *this;
}
//
//	Set title (filename + extension) only, keep the rest.
//
CFileName&
CFileName::SetTitle(LPCTSTR szTitle) {
	_tsplitpath_s(szTitle, NULL, 0, NULL, 0, m_szName, sizeof m_szName / sizeof m_szName[0], m_szExt, sizeof m_szExt / sizeof m_szExt[0]);
	return *this;
}
//
//	Set directory (and drive) only, keep the rest.
//
CFileName&
CFileName::SetDir(LPCTSTR szDir) {
	_tsplitpath_s(szDir, m_szDrive, sizeof m_szDrive / sizeof m_szDrive[0], m_szDir, sizeof m_szDir / sizeof m_szDir[0], NULL, 0, NULL, 0);
	return *this;
}
//
//	Set drive only, keep the rest.
//
CFileName&
CFileName::SetDrive(LPCTSTR szDrive) {
	_tsplitpath_s(szDrive, m_szDrive, sizeof m_szDrive / sizeof m_szDrive[0], NULL, 0, NULL, 0, NULL, 0);
	return *this;
}
//
//  Set the full name, all components.
//
CFileName&
CFileName::Set(LPCTSTR szFullName) {
	Split(szFullName);
	return *this;
}

/// \brief Merge the current directory with the possibly partial (relative) specification already present.
///
/// If the current name already has a drive specified, then we should not merge that
/// with the current directory, but assume that it's already fully specified.
/// \param szCurDir A fully qualified name for the notion of current directory, including drive designator
/// \return A reference to 'this'
CFileName&
CFileName::SetCurDir(LPCTSTR szCurDir) {
	// If there's no drive in the current path, or the drive is the same as the provided current directory
	if (!m_szDrive[0] || _tcsnicmp(m_szDrive, szCurDir, 1) == 0) {
		// If there's either no directory specified, or it's not an absolute directory
		if (!m_szDir[0] || m_szDir[0] != _T('\\')) {
			_tcsncpy_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], szCurDir, sizeof m_szWorkName / sizeof m_szWorkName[0]);
			m_szWorkName[sizeof m_szWorkName / sizeof m_szWorkName[0] - 1] = _T('\0');
			ASSCHK(PathAppend(m_szWorkName, m_szDir), _T("PathAppend() failed"));
			ASSCHK(PathCanonicalize(m_szDir, m_szWorkName), _T("PathCanonicalize failed"));

			_tcsncpy_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], m_szDir, sizeof m_szWorkName / sizeof m_szWorkName[0]);
			m_szWorkName[sizeof m_szWorkName / sizeof m_szWorkName[0] - 1] = _T('\0');
			SetDir(m_szWorkName);
		}
	}
	return *this;
}
//
//	Override the components that exist in the given path
//
CFileName&
CFileName::Override(LPCTSTR szPath) {
	CFileName Path;
	Path.Set(szPath);

	// The VS 2005 version of splitpath requires both pointer and count to be zero when ignoring a component.
	_TCHAR* szDrive = NULL, * szDir = NULL, * szName = NULL, * szExt = NULL;
	size_t ccDrive = 0, ccDir = 0, ccName = 0, ccExt = 0;
	if (Path.m_szDrive[0] != _T('\0')) {
		szDrive = m_szDrive;
		ccDrive = sizeof m_szDrive / sizeof m_szDrive[0];
	}
	if (Path.m_szDir[0] != _T('\0')) {
		szDir = m_szDir;
		ccDir = sizeof m_szDir / sizeof m_szDir[0];
	}
	if (Path.m_szName[0] != _T('\0')) {
		szName = m_szName;
		ccName = sizeof m_szName / sizeof m_szName[0];
	}
	if (Path.m_szExt[0] != _T('\0')) {
		szExt = m_szExt;
		ccExt = sizeof m_szExt / sizeof m_szExt[0];
	}

	_tsplitpath_s(szPath, szDrive, ccDrive, szDir, ccDir, szName, ccName, szExt, ccExt);

	return *this;
}
/// \brief Convert dot to dash in extension.
/// Change the dot in an extension (if any) to a dash,
/// effectively removing the extension and adding it to
/// the file name instead.
/// \return A reference to *this.
CFileName&
CFileName::DashExt() {
	if (m_szExt[0] == _T('.')) {
		m_szExt[0] = _T('-');
	}
	_tcscat_s(m_szName, sizeof m_szName / sizeof m_szName[0], m_szExt);
	m_szExt[0] = _T('\0');
	return *this;
}

//
//	Delete the extension, keep the rest
//
CFileName&
CFileName::DelExt() {
	m_szExt[0] = TCHAR(0);
	return *this;
}
//
//	Move existing extension to filename, add the new extension
//	keep the rest
//
CFileName&
CFileName::AddExt(LPCTSTR szExt) {
	_tcscat_s(m_szName, sizeof m_szName / sizeof m_szName[0], m_szExt);
	_tcscpy_s(m_szExt, sizeof m_szExt / sizeof m_szExt[0], szExt);
	Split(Get());
	return *this;
}

/// \brief Append a name to the full as it is
/// \return *this
CFileName&
CFileName::AddName(LPCTSTR szName) {
	const TCHAR* sz = Get();
	bool fNoExtraBackslash = false;
	if (sz[0]) {
		fNoExtraBackslash = sz[_tcslen(sz) - 1] == _T('\\');
	}

	TCHAR szWorkName[sizeof m_szWorkName / sizeof m_szWorkName[0]];
	_tcscpy_s(szWorkName, sizeof szWorkName / sizeof szWorkName[0], Get());
	_tcscat_s(szWorkName, sizeof szWorkName / sizeof szWorkName[0], fNoExtraBackslash ? _T("") : _T("\\"));
	_tcscat_s(szWorkName, sizeof szWorkName / sizeof szWorkName[0], szName);

	Split(szWorkName);
	return *this;
}

//
//	Get a fully qualified file name
//
LPCTSTR
CFileName::Get() {
	_tmakepath_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], m_szDrive, m_szDir, m_szName, m_szExt);
	return m_szWorkName;
}
//
//	Get the title (filename + extension)
//
LPCTSTR
CFileName::GetTitle() {
	_tmakepath_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], NULL, NULL, m_szName, m_szExt);
	return m_szWorkName;
}
//
//	Get the Drive + Directory
//
LPCTSTR
CFileName::GetDir() {
	_tmakepath_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], m_szDrive, m_szDir, NULL, NULL);
	return m_szWorkName;
}
//
//	Get the RootDir, i.e. Drive + \
//
LPCTSTR
CFileName::GetRootDir() {
	_tmakepath_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], m_szDrive, _T("\\"), NULL, NULL);
	return m_szWorkName;
}
//
//  Get the name
//
LPCTSTR
CFileName::GetName() {
	_tmakepath_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], NULL, NULL, m_szName, NULL);
	return m_szWorkName;
}
//
//  Get the extension
//
LPCTSTR
CFileName::GetExt() {
	_tmakepath_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], NULL, NULL, NULL, m_szExt);
	return m_szWorkName;
}
//
//	Get the fully qualified name, and quote it.
//
LPCTSTR
CFileName::GetQuoted() {
	Get();
	MoveMemory(&m_szWorkName[1], m_szWorkName, (_tcslen(m_szWorkName) + 1) * sizeof TCHAR);
	m_szWorkName[0] = _T('"');
	_tcscat_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], _T("\""));
	return m_szWorkName;
}
//
//	for internal use - split into all components.
//
void
CFileName::Split(LPCTSTR szFileName) {
	// The 'new' _tsplitpath_s has new semantics and won't allow an empty string, but this is what we want:
	if (szFileName == NULL || szFileName[0] == _T('\0')) {
		m_szDrive[0] = _T('\0');
		m_szDir[0] = _T('\0');
		m_szName[0] = _T('\0');
		m_szExt[0] = _T('\0');
		return;
	}
	_tsplitpath_s(szFileName, m_szDrive, sizeof m_szDrive / sizeof m_szDrive[0], m_szDir, sizeof m_szDir / sizeof m_szDir[0], m_szName, sizeof m_szName / sizeof m_szName[0], m_szExt, sizeof m_szExt / sizeof m_szExt[0]);
}
/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001 Svante Seleborg/Axon Data, All rights reserved.

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
	CRegistry.cpp					Registry manipulating class

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2002-08-17				Rel 1.2.1	Initial
*/
#include	"StdAfx.h"
#include    "CRegistry.h"
#include    "Utility.h"
#include    "shlwapi.h"
#include    <memory>

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CRegistry.cpp"

CRegistry::CRegistry(HKEY hRootKey, LPCTSTR szKey, LPCTSTR szValueName) {
	m_hRootKey = hRootKey;
	m_hRegKey = NULL;
	m_szValueName = NULL;
	if (szKey != NULL) Key(szKey);
	if (szValueName != NULL) m_szValueName = CopySz(szValueName);
}

CRegistry::~CRegistry() {
	if (m_hRegKey != NULL) RegCloseKey(m_hRegKey);
	if (m_szValueName != NULL) delete m_szValueName;
}

CRegistry& CRegistry::Root(HKEY hRootKey) {
	if (m_hRegKey != NULL) {
		RegCloseKey(m_hRegKey);
		m_hRegKey = NULL;
	}
	m_hRootKey = hRootKey;
	return *this;
}

CRegistry& CRegistry::HKey(HKEY hKey) {
	if (m_hRegKey != NULL) {
		RegCloseKey(m_hRegKey);
		m_hRegKey = NULL;
	}
	m_hRegKey = hKey;
	return *this;
}

CRegistry& CRegistry::Key(LPCTSTR szKey) {
	if (m_hRegKey != NULL) {
		RegCloseKey(m_hRegKey);
		m_hRegKey = NULL;
	}

	// Assert that we really specify a subkey, otherwise RegOpenKeyEx opens the current m_hRootKey again - we do NOT want that,
	// if this is used later for deletion we risk deleting the entire registry sub-tree... Not good.
	CAssert(szKey && szKey[0] != _T('\0')).App(ERR_ARGUMENT, _T("CRegistry::Key(LPCTSTR szKey)")).Throw();

	LONG lRes = RegOpenKeyEx(m_hRootKey, szKey, 0, KEY_READ | KEY_WRITE, &m_hRegKey);
	// We allow silent failure if the key is no found. This is ok if we only want to
	// read it...
	if (lRes != ERROR_FILE_NOT_FOUND) {
		if (lRes != ERROR_ACCESS_DENIED) {
			CAssertEq(lRes, ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("CRegistry::Key() [RegOpenKeyEx(1)]")).Throw();
		}
		else {
			// If we can't get write access, let's try for read access.
			CAssert(RegOpenKeyEx(m_hRootKey, szKey, 0, KEY_READ, &m_hRegKey) == ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("CRegistry::Key() [RegOpenKeyEx(2)]")).Throw();
		}
	}
	return *this;
}
//
//  Create and open a handle to a registry key, using FormatMessage pattern
//  to fill in.
//
//  Use %1 to fill in the pattern.
//
CRegistry& CRegistry::CreateKey(LPCTSTR szKeyFormat, LPCTSTR szFillIn) {
	LPTSTR szFormattedKey;
	CAssert(FormatMessage(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY,
		szKeyFormat,
		0,
		0,
		(LPTSTR)&szFormattedKey,
		0,
		(va_list*)&szFillIn)).Sys(MSG_SYSTEM_CALL, _T("CRegistry::CreateKey() [FormatMessage()]")).Throw();
	if (m_hRegKey != NULL) {
		RegCloseKey(m_hRegKey);
		m_hRegKey = NULL;
	}
	ULONG lDisp;
	LONG lRes = RegCreateKeyEx(m_hRootKey,
		szFormattedKey,
		0,
		NULL,
		0,
		KEY_ALL_ACCESS,
		NULL,
		&m_hRegKey,
		&lDisp);
	LocalFree(szFormattedKey);
	CAssertEq(lRes, ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("CRegistry:CreateKey() [RegCreateKeyEx()]")).Throw();
	return *this;
}

CRegistry& CRegistry::Value(LPCTSTR szValueName) {
	if (m_szValueName != NULL) {
		delete m_szValueName;
		m_szValueName = NULL;
	}
	m_szValueName = CopySz(szValueName);
	return *this;
}

DWORD CRegistry::GetDword(DWORD dwDefault) {
	// We interpret a NULL hKey as 'not found', and thus return
	// the default value.
	if (m_hRegKey == NULL) {
		return dwDefault;
	}
	DWORD dwData, dwLen = sizeof dwData, dwType;
	LONG lRes = RegQueryValueEx(m_hRegKey, m_szValueName, NULL, &dwType, (BYTE*)&dwData, &dwLen);
	if (lRes == ERROR_FILE_NOT_FOUND) {
		dwData = dwDefault;
	}
	else {
		CAssertEq(lRes, ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("CRegistry::GetDword() [ReqQueryValueEx]")).Throw();
		CAssert(dwLen == 4).App(ERR_UNSPECIFIED, _T("CRegistry::GetDword() [dwLen != 4]")).Throw();
	}
	return dwData;
}

void CRegistry::SetDword(DWORD dwValue) {
	CAssertEq(RegSetValueEx(m_hRegKey,
		m_szValueName,
		0,
		REG_DWORD,
		(BYTE*)&dwValue,
		sizeof dwValue), ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("CRegistry::SetDword() [RegSetValueEx()]")).Throw();
}

void* CRegistry::GetBinary(int* nLen) {
	return NULL;
}

void CRegistry::SetBinary(void* vData, int nLen) {
}
//
//  This returns a new'ed string, please remember to delete...
//
LPTSTR CRegistry::GetSz(LPCTSTR szDefault) {
	// If the registry does not exist - return default!
	if (m_hRegKey == NULL) {
		return CopySz(szDefault);
	}

	DWORD dwLen, dwType;
	// First get the length of the string
	LONG lRes = RegQueryValueEx(m_hRegKey, m_szValueName, NULL, &dwType, NULL, &dwLen);
	if (lRes == ERROR_FILE_NOT_FOUND) {
		return CopySz(szDefault);
	}
	CAssertEq(lRes, ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("CRegistry::GetSz() [RegQueryValueEx()]")).Throw();
	// Must be reg_sz, otherwise default return.
	if (dwType != REG_SZ) {
		return CopySz(szDefault);
	}

	dwLen = ((dwLen / sizeof TCHAR) + 1) * sizeof TCHAR; // Round upwards, just in case...
	LPTSTR szValue = new TCHAR[dwLen / sizeof TCHAR]; // Yes, ReqQuery returns the size in bytes...
	ASSPTR(szValue);

	lRes = RegQueryValueEx(m_hRegKey, m_szValueName, NULL, &dwType, (BYTE*)szValue, &dwLen);
	if (lRes != ERROR_SUCCESS) {
		delete szValue;
		CAssert(FALSE, lRes).Sys(MSG_SYSTEM_CALL, _T("CRegistry::GetSz() [RegQueryValueEx()]")).Throw();
	}
	return szValue;
}

void CRegistry::SetSz(LPCTSTR szValue) {
	CAssertEq(RegSetValueEx(m_hRegKey,
		m_szValueName,
		0,
		REG_SZ,
		(CONST BYTE*)szValue,
		(DWORD)((_tcslen(szValue) + 1) * sizeof TCHAR)), ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("CRegistry::SetSz() [RegSetValueEx()]")).Throw();
}

void CRegistry::SetSz(LPCTSTR szValueFormat, LPCTSTR szFillIn) {
	LPTSTR szFormattedValue;
	CAssert(FormatMessage(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY,
		szValueFormat,
		0,
		0,
		(LPTSTR)&szFormattedValue,
		0,
		(va_list*)&szFillIn)).Sys(MSG_SYSTEM_CALL, _T("CRegistry::SetSz() [FormatMessage()]")).Throw();
	LONG lRes = RegSetValueEx(m_hRegKey,
		m_szValueName,
		0,
		REG_SZ,
		(CONST BYTE*)szFormattedValue,
		(DWORD)((_tcslen(szFormattedValue) + 1) * sizeof TCHAR));
	// First free the buffer, then assert...
	LocalFree(szFormattedValue);
	CAssertEq(lRes, ERROR_SUCCESS).Sys(MSG_SYSTEM_CALL, _T("CRegistry::SetSz() [RegSetValueEx()]")).Throw();
}

void
CRegistry::DelValue() {
	CAssert(m_hRegKey != NULL && m_szValueName != NULL).App(MSG_INTERNAL_ERROR, _T("CRegistry::DelValue()")).Throw();

	std::auto_ptr<TCHAR> szMsg(FormatSz(_T("CRegistry::DelValue() [RegDeleteValue(%1)]"), m_szValueName));
	LONG lRes = RegDeleteValue(m_hRegKey, m_szValueName);
	CAssert(lRes == ERROR_FILE_NOT_FOUND || lRes == ERROR_SUCCESS, lRes).Sys(MSG_SYSTEM_CALL, szMsg.get()).Throw();
}

/// \brief Delete the specified subkey - it must be empty or non-existing
void
CRegistry::DelSubHKey(HKEY hKey, LPCTSTR szSubKey) {
	// Assert that we have valid arguemnts
	CAssert(hKey != NULL).App(ERR_ARGUMENT, _T("CRegistry::DelSubHKey(HKEY hKey, ...)")).Throw();
	CAssert(szSubKey && szSubKey[0]).App(ERR_ARGUMENT, _T("CRegistry::DelSubHKey(LPCTSTR szSubKey)")).Throw();

	std::auto_ptr<TCHAR> szMsg(FormatSz(_T("CRegistry::DelSubHKey() [RegDeleteKey(%1)]"), szSubKey));
	LONG lRes = SHDeleteEmptyKey(hKey, szSubKey);
	CAssert(lRes == ERROR_FILE_NOT_FOUND || lRes == ERROR_SUCCESS, lRes).Sys(MSG_SYSTEM_CALL, szMsg.get()).Throw();
}

/// \brief Delete the specified subkey - it must be empty or non-existing
void
CRegistry::DelSubKey(LPCTSTR szSubKey) {
	DelSubHKey(m_hRegKey, szSubKey);
}

/// \brief Delete recursively the specified subkey, empty or not
void
CRegistry::DelSubHKeyRecurse(HKEY hKey, LPCTSTR szSubKey) {
	// Assert that we have valid arguemnts, this is fairly dangerous otherwise...
	CAssert(hKey != NULL).App(ERR_ARGUMENT, _T("CRegistry::DelSubHKeyRecurse(HKEY hKey, ...)")).Throw();
	CAssert(szSubKey && szSubKey[0]).App(ERR_ARGUMENT, _T("CRegistry::DelSubHKeyRecurse(..., LPCTSTR szSubKey)")).Throw();

	std::auto_ptr<TCHAR> szMsg(FormatSz(_T("CRegistry::DelSubHKeyRecurse() [SHDeleteKey(%1)]"), szSubKey));
	DWORD dwRes = SHDeleteKey(hKey, szSubKey);
	CAssert(dwRes == ERROR_FILE_NOT_FOUND || dwRes == ERROR_SUCCESS, dwRes).Sys(MSG_SYSTEM_CALL, szMsg.get()).Throw();
}

/// \brief Delete recursively the specified subkey, empty or not
void CRegistry::DelSubKeyRecurse(LPCTSTR szSubKey) {
	DelSubHKeyRecurse(m_hRegKey, szSubKey);
}
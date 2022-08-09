#ifndef	_CREGISTRY
#define	_CREGISTRY
/*
    @(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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

	The author may be reached at mailto:software@axantum.com and http://www.axantum.com
----
	CRegistry.h 					Registry manipulating class

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2002-08-17              Rel 1.2.1 Initial
*/
//
//  Helper class to work with the registry. Throws TAssert on error.
//
class CRegistry {
    HKEY m_hRegKey;
    HKEY m_hRootKey;
    LPTSTR m_szValueName;
public:
    CRegistry(HKEY hRootKey = NULL, LPCTSTR szKey = NULL, LPCTSTR szValue = NULL);
    ~CRegistry();

    CRegistry& Root(HKEY hRootKey);
    CRegistry& Key(LPCTSTR szKey);
    CRegistry& HKey(HKEY hKey);
    CRegistry& CreateKey(LPCTSTR szKeyFormat, LPCTSTR szFillIn = _T(""));
    CRegistry& Value(LPCTSTR szValue);

    HKEY GetHKey() { return m_hRegKey; }

    DWORD GetDword(DWORD dwDefault = 0);
    void SetDword(DWORD dwValue);

    void *GetBinary(int *nLen = NULL);
    void SetBinary(void *vData, int nLen);

    LPTSTR GetSz(LPCTSTR szDefault = _T(""));
    void SetSz(LPCTSTR szValue);
    void SetSz(LPCTSTR szValueFormat, LPCTSTR szFillIn);

    void DelValue();

	static void DelSubHKey(HKEY hKey, LPCTSTR szSubKey);
    void DelSubKey(LPCTSTR szSubKey);
    static void DelSubHKeyRecurse(HKEY hKey, LPCTSTR szSubKey);
    void DelSubKeyRecurse(LPCTSTR szSubKey);
};
#endif
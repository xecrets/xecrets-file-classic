#ifndef	_CFILENAME
#define	_CFILENAME
/*
    @(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2023 Svante Seleborg/Axon Data, All rights reserved.

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
	CFileName.h						File name related utility operations.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial
									2001-12-01				Added CTempDir

*/
//
//	File Name Operation Routines
//
class CFileName {
public:
	CFileName();
	CFileName(LPCTSTR szFileName);

	CFileName& SetPath2ExeName(HINSTANCE hInstance = NULL);
	CFileName& SetPath2TempDir();
    CFileName& SetPath2SysTempDir();
	CFileName& SetName(LPCTSTR szFileName);
	CFileName& SetExt(LPCTSTR szExt);
	CFileName& SetTitle(LPCTSTR szTitle);
	CFileName& SetDir(LPCTSTR szDir);
    CFileName& SetDrive(LPCTSTR szDrive);
    CFileName& Set(LPCTSTR szFullName);
    CFileName& SetCurDir(LPCTSTR szCurDir);
	CFileName& Override(LPCTSTR szPath);

    CFileName& DashExt();                   ///< Convert dot to dash in extension.
    CFileName& DelExt();
	CFileName& AddExt(LPCTSTR szExt);
    CFileName& AddName(LPCTSTR szName);

	LPCTSTR Get();
	LPCTSTR GetDir();
    LPCTSTR GetRootDir();
    LPCTSTR GetName();
    LPCTSTR GetExt();
	LPCTSTR GetTitle();
	LPCTSTR GetQuoted();

protected:
	void Split(LPCTSTR szFileName);

	TCHAR m_szWorkName[_MAX_PATH + sizeof TCHAR * 2];	// Room for quotes as well.
	TCHAR m_szDrive[_MAX_DRIVE];
	TCHAR m_szDir[_MAX_DIR];
	TCHAR m_szName[_MAX_FNAME];
	TCHAR m_szExt[_MAX_EXT];
};
#endif	_CFILENAME
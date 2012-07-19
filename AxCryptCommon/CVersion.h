#ifndef	_CVERSION
#define	_CVERSION
/*
    @(#) $Id$

	Ax Crypt - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
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
	CVersion.h						Version

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
//
//	Versioning info in resource record
//
//	Minuscle is increased for bugfixes.
//	Minor is increased for other changes, possibly user visible.
//	Major is increased for major functionality upgrades or releases.
//
//	FileMinor is increased when the file-format changes, but in a way that is properly
//		handled even by older versions, i.e. ignored.
//	FileMajor is increased if we ever change the file such that older programs cannot
//		read the new format.
//
//	Define 'Beta', 'Release Candidate' or nothing in SpecialBuild in resources
//
// Change from ver 1: Use all 16 bytes instead of 4 of key wrapping salt.
// Change from ver 2: Allow conditional compression. For some reason this causes more back-
//                    ward problems than it should, but these releases are so near, we'll
//                    just up the version and say no backwards.
// 3.1: Added IdTag, but should be fully compatible both ways.
//
#include "CFmtMsg.h"
#include "Utility.h"

// File format Version 3.2 adds support for Unicode file names, eUnicodeFileNameInfo
const BYTE oFileMajor = 3;
const BYTE oFileMinor = 2;
//
class CVersion {
    static HINSTANCE m_hInstance;
	VS_FIXEDFILEINFO *m_pFixedFileInfo;
	void *m_pFileVersionInfo;
    LPTSTR m_szLegalCopyright;
    LPTSTR m_szCompanyName;
    LPTSTR m_szFileDescription;
    CPtrTo<TCHAR> m_szExtProductName;
	CFmtMsg m_szString;
    CPtrTo<TCHAR> m_szIntProductName;
    void Init(const _TCHAR *szFileName);
public:
    static void Init(HINSTANCE hInstance);
	CVersion(HINSTANCE hInstance = NULL);
    CVersion(const _TCHAR *szFileName);
	~CVersion();
	WORD FileMajor();
	WORD FileMinor();
	WORD Major();
	WORD Minor();
	WORD Minuscle();
	WORD Patch();
	WORD MajorFileVersion();
	WORD MinorFileVersion();
	WORD MinuscleFileVersion();
	WORD PatchFileVersion();
	LPCTSTR ExtProductName();    // External, visible, name
    LPCTSTR IntProductName();    // Internal, for mutexes, reg-keys etc, etc.
    LPCTSTR CompanyName();       // Company name, from resource
    LPCTSTR LegalCopyright();    // Copyright string, from resource
    LPCTSTR FileDescription();   // File Description, from resource
    const _TCHAR *FileVersionString();            ///< Formatted string with File Version info from resource
    wstring GenericVersionString(); ///< A fixed-format version string with all 4 elements and dot between.
	LPCTSTR String(bool fShowNoVersion = false); ///< Formatted string with External product name + product version info
};
//
//	Some helpers to find out the OS version as well.
//
class COsVersion {
	OSVERSIONINFO m_stOsVersion;
public:
	COsVersion();
	BOOL IsWin95();
	BOOL IsWin98();
	BOOL IsWinME();
	BOOL IsWin2000();
	BOOL IsWinNT();
	BOOL IsWinXP();
	BOOL IsWin9x();
	BOOL IsWinNx();
};
#endif	_CVERSION
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
	CFileTemp.cpp					Actions on temporary files and directories

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2002-01-22				Initial
*/
#include	"StdAfx.h"
#include	"CFileTemp.h"
#include	"CCryptoRand.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CFileTemp.cpp"
//
//	Create a temporary file.
//
CFileTemp&
CFileTemp::New() {
	SetPath2TempDir();
	// Now make a temporary file in the given directory.
	CAssert(GetTempFileName(GetDir(), (LPTSTR)&gszAxCryptFileExt[1], 0, m_szWorkName)).Sys(MSG_GET_TEMP, m_szWorkName).Throw();
	Split(m_szWorkName);
	return *this;
}
//
//	Ensure that the temporary directory is removed along with this object.
//
CTempDir::~CTempDir() {
	if (m_szDir[0]) {
		DWORD dwLastError;
		if (dwLastError = RemoveDir()) {
			CMessage().SysMsg(dwLastError).AppMsg(WRN_DIR_NOT_EMPTY, m_szDir).ShowWarning(MB_OK);
		}
#ifdef NOTOBSOLETEAFTERALL
		int i = 0;
		while (!RemoveDirectory(GetDir())) {
			switch (GetLastError()) {
				// And of course Win 9x and 2K have different codes for the same thing...
			case ERROR_PATH_NOT_FOUND:
			case ERROR_FILE_NOT_FOUND:
				return;
				// For whatever reason, some apps seem to lock the temp-directory for deletion for a while after
				// the app is actually exited. This is not critical here - all else is already release so we may
				// well wait for these 10 seconds...
			case ERROR_SHARING_VIOLATION:
				if (i++ < 20) {	// 10 seconds...
					Sleep(500);	// Some apps seem to need a little extra time to clean up..
					break;
				}
				// fall through
			case ERROR_DIR_NOT_EMPTY:
			default:
				CMessage().SysMsg(GetLastError()).AppMsg(WRN_DIR_NOT_EMPTY, m_szDir).ShowWarning(MB_OK);
				return;
			}
		}
#endif
	}
}
//
//	Make a new sub-directory in the temp directory.
//
CTempDir&
CTempDir::New() {
	for (int i = 0; i < 10; i++) {
		SetPath2TempDir();
		// We do happen to have a decent pseudo random number generator, let's use it!
		WORD wRandom;
		pgPRNG->RandomFill(&wRandom, sizeof wRandom);

		_stprintf_s(m_szWorkName, sizeof m_szWorkName / sizeof m_szWorkName[0], _TT("%s%04X\\"), (LPTSTR)&gszAxCryptFileExt[1], wRandom);
		SetDir(CStrPtr(m_szDrive) + CStrPtr(m_szDir) + CStrPtr(m_szWorkName));
		if (CreateDirectory(Get(), NULL)) {
			return *this;
		}
		else {
			CAssert(GetLastError() == ERROR_ALREADY_EXISTS).Sys().Throw();
		}
	}
	SetPath2TempDir();
	CAssert(FALSE).App(ERR_TEMP_DIR, Get()).Throw();
	return *this;
}
//
//	Return the name of the temporary directory.
//
LPCTSTR CTempDir::Get() {
	return CFileName::Get();
}
//
// For convenience sake we want a version that returns CTempDir&
//
CTempDir&
CTempDir::SetPath2TempDir() {
	CFileName::SetPath2TempDir();
	return *this;
}
//
//	Empty and delete the entire temp directory, as well as sub-directories.
//
DWORD
CTempDir::RemoveDir() {
	// Lock reference to the current directory while we're operating with it.
	CCriticalSection critCurDir(&gCurrentDirectoryCritical, TRUE);

	return RmDir(GetDir());
}
//
//	Actual, recursive, worker to delete a directory and it's contents.
//	It fails silently on failure to delete a file or directory, but does
//	the best it can, i.e. continues to do as much as possible.
//
//  It will return zero if everything ok and the directory removed, otherwise it
//  will return the last error code known to cause a failure in the deletion process.
//
//  The caller must assure thread-safe access to process current directory.
//
DWORD
CTempDir::RmDir(LPCTSTR szDir) {
	// Get length of the buffer required, and then put the current directory there.
	DWORD dwLen = GetCurrentDirectory(0, NULL);
	CAssert(dwLen).Sys(MSG_SYSTEM_CALL, _T("CFileName::RmDir() [GetCurrentDirectory(0)]")).Throw();
	CPtrTo<TCHAR> szCurDir = new TCHAR[dwLen];	// Self-destructing pointer.
	ASSPTR(szCurDir);

	CAssert(GetCurrentDirectory(dwLen, szCurDir)).Sys(MSG_SYSTEM_CALL, _T("CFileName::RmDir() [GetCurrentDirectory(szCurDir)]")).Throw();

	DWORD dwReturn = 0;
	// Fail silently if the directory just does not exist.
	if (!SetCurrentDirectory(szDir)) {
		// Win 95/98 and others use different error codes for the same thing...
		CAssert((GetLastError() == ERROR_PATH_NOT_FOUND) || (GetLastError() == ERROR_FILE_NOT_FOUND)).Sys(MSG_SYSTEM_CALL, _T("CFileName::RmDir() [SetCurrentDirectory(szDir)]")).Throw();
		return GetLastError();
	}

	int iRetry = 2;
	bool fNeedRetry = false;
	do {
		fNeedRetry = false;
		WIN32_FIND_DATA stFindData;
		CHFind hFindFile = FindFirstFile(_T("*.*"), &stFindData);	// Self-closing handle
		CAssert(hFindFile.IsValid()).Sys(MSG_SYSTEM_CALL, _T("CFileName::RmDir() [FindFirstFile()]")).Throw();

		do {
			if (stFindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (_tcscmp(stFindData.cFileName, _T(".")) && _tcscmp(stFindData.cFileName, _T(".."))) {
					dwReturn = dwReturn || RmDir(stFindData.cFileName);
				}
			}
			else {
				try {
					// Try to remove read-only attributes, if any, on files in the temp-directory.
					DWORD dwAttrib = GetFileAttributes(stFindData.cFileName);
					CAssert(dwAttrib != INVALID_FILE_ATTRIBUTES).Sys(MSG_SYSTEM_CALL, _T("CTempDir::RmDir() [GetFileAttributes]")).Throw();
					if ((dwAttrib & FILE_ATTRIBUTE_READONLY) != 0) {
						CAssert(SetFileAttributes(stFindData.cFileName, dwAttrib & ~FILE_ATTRIBUTE_READONLY)).Sys(MSG_SYSTEM_CALL, _T("CTempDir::RmDir() [SetFileAttributes]")).Throw();
					}

					CFileIO utFile2Delete;
					utFile2Delete.Open(stFindData.cFileName, TRUE, GENERIC_READ | GENERIC_WRITE, 0);
					utFile2Delete.WipeTemp(NULL, m_nWipePasses);
					utFile2Delete.Close();
				}
				catch (TAssert utErr) {
					dwReturn = GetLastError();
					fNeedRetry = true;
				}
			}
		} while (FindNextFile(hFindFile, &stFindData));
		CAssert(GetLastError() == ERROR_NO_MORE_FILES).Sys(MSG_SYSTEM_CALL, _T("CFileName::RmDir() [FindNextFile()]")).Throw();
		CAssert(hFindFile.Close()).Sys(MSG_SYSTEM_CALL, _T("CFileName::RmDir() [hFindFile.Close()]")).Throw();
		if (fNeedRetry) {
			// It's an inexact science... Give the apps some time to let go of the files.
			Sleep(100);
		}
	} while (fNeedRetry && --iRetry);

	CAssert(SetCurrentDirectory(szCurDir)).Sys(MSG_SYSTEM_CALL, _T("CFileName::RmDir() [SetCurrentDirectory(szCurDir)]")).Throw();
	if (!RemoveDirectory(szDir)) {
		dwReturn = GetLastError();
	}
	return dwReturn;
}
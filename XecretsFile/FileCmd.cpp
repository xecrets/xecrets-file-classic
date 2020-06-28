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
	FileCmd.cpp						Implementation of file operation commands from main code.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001-12-02				Initial for 0.0b4
									2002-02-12              Use IsValid() for CHandle vars.
									2002-07-25              Rev 1.2
									2002-08-22              Rel 1.2.2
									2003-07-07              Rel 1.4.1d1 Enable FILE_FLAG_WRITE_THROUGH
															for encrypt/decrypt/re-encrypt files due to
															possible cause of corrupion in network
															environments.
									2004-01-06              Rel 1.5 - Self Decrypting Executable
*/
#include	"StdAfx.h"
//
#include	"shellapi.h"
#include	"shlobj.h"
#include	"CWrapper.h"
#include	"CFileTemp.h"
#include	"CChildProc.h"
#include	"Dialog.h"
#include	"../XecretsFileCommon/CVersion.h"
#include    "FileCmd.h"
#include	"../XecretsFileCommon/Utility.h"
#include    "../XecretsFileCommon/CRegistry.h"
#include    "../AxSigLib/CTrialMgr.h"
#include    "../AxSigLib/CRestrictMgr.h"
#include    "DlgLicense.h"
#include	"DlgRegistration.h"

#include	<io.h>
#include	<fcntl.h>
#include    <commdlg.h>
#include    <shlwapi.h>
#include <shellapi.h>
#include    <limits.h>
#include <Winnetwk.h>

#include    <memory>
#include    <list>
using namespace std;

#include    "../AxPipe/CFileMap.h"
#include    "../AxPipe/CPipeFindSync.h"

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Mpr.lib")

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "FileCmd.cpp"
//
//  Helper class to handle read-only situations.
//
static const DWORD dwAttribMask = FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_TEMPORARY;

class CReadOnlyMgr {
	std::wstring m_szFileName;           // Local copy of file name.
	bool m_isReadOnly;

	DWORD GetAttributes() throw (TAssert) {
		DWORD dwAttrib = GetFileAttributes(m_szFileName.c_str());
		DWORD dwLastError = GetLastError();
		auto_ptr<TCHAR> szMsg(FormatSz(_T("CReadOnlyMgr::GetAttributes() [GetFileAttributes(%1)]"), m_szFileName.c_str()));
		CAssert(dwAttrib != INVALID_FILE_ATTRIBUTES, dwLastError).Sys(MSG_SYSTEM_CALL, szMsg.get()).Throw();
		return dwAttrib;
	}

	// Set attributes, return true if ok, false if 'expected' error, such as access denied. Otherwise throw exception.
	bool SetAttributes(DWORD dwAttrib) throw (TAssert) {
		auto_ptr<TCHAR> szMsg(FormatSz(_T("CReadOnlyMgr::SetAttributes() [SetFileAttributes(%1)]"), m_szFileName.c_str()));
		if (!SetFileAttributes(m_szFileName.c_str(), dwAttrib & dwAttribMask)) {
			switch (GetLastError()) {
			case ERROR_SUCCESS:
				break;
			case ERROR_ACCESS_DENIED:
			case ERROR_WRITE_PROTECT:
			case ERROR_LOCK_VIOLATION:
				return false;
				break;
			default:
				CAssert(FALSE, GetLastError()).Sys(MSG_SYSTEM_CALL, szMsg.get()).Throw();
			}
		}
		return true;
	}
public:
	// Find out what we can about the file.
	CReadOnlyMgr(const TCHAR* szFileName) {
		// Save a local copy of the file-name
		m_szFileName = szFileName;
		m_isReadOnly = CheckIfReadOnly();
	}

	/// \brief Check if a file is potentially writeable at all
	/// This is a worst case check, ensuring that we can read it,
	/// write it, and not share it. We do check for attribute read only
	/// and if we can override that.
	/// \return true only if we can.
	void AssWriteable() throw (TAssert) {
		// First we have to determine if the file is read-only, before we do the test...
		bool fIsReadOnly = IsReadOnly();
		if (fIsReadOnly) {
			if (!SetReadWrite()) {
				// We can't change the attribute
				CAssert(FALSE, GetLastError()).Sys().Throw();
			}
		}
		// Determine if we only have read permissions (or no permissions)
		// The easiest and most straight-forward and compatible way appears to
		// be to simply open it...
		try {
			CFileIO fileTest;
			// Try to open the file with read/write permissions (like we will later)
			fileTest.Open(m_szFileName.c_str(), FALSE, GENERIC_READ | GENERIC_WRITE);
			fileTest.Close();
		}
		catch (TAssert utErr) {
			// We don't really need to check for any specific problems - if we
			// can't write it, we can't, so we re-throw it and let the caller
			// handle it (after resetting the ReadOnly-bit if necessary.)
			if (fIsReadOnly) {
				SetReadOnly();
			}
			throw;
		}
		if (fIsReadOnly) {
			SetReadOnly();
		}
	}

	/// \brief Check by trying to open if a file is read only
	/// There appears to be no reasonable way to actually check the 'share permissions' of a network share! NetShareGetInfo at level 2
	/// requires begin admin or similar. WMI seems like extreme overkill and will probably just cause a bunch of other problems.
	/// we fall back to just trying to open it for writing. We do attempt to determine if it's a networked resource, otherwise just use
	/// file-attributes.
	bool CheckIfReadOnly() {
		// Since we want to avoid network access, let's first just see if it is read only by way of actual
		// file attributes - if it is, that's enough info. Only if it's not do we need to check further for the
		// typical case of file being read/write, but accessed via a share that is read only.
		if ((GetAttributes() & FILE_ATTRIBUTE_READONLY) == FILE_ATTRIBUTE_READONLY) {
			return true;
		}

		// The documenation and implementation of WNetGetUniversalName is incorrect. The documentation states:
		//   If the function fails because the buffer is too small, this location receives the required buffer size, and the function returns ERROR_MORE_DATA.
		// This statement is only correct up to '4' - the size of a pointer. The problem is that it actually writes the resulting string directly afterwards,
		// just overwriting whatever is there! There is no way to know how much this data is, except the 'approximate' maximum size of a UNC path 32767 in chars,
		// approximate because '\\?\' may expand.
		// See http://social.msdn.microsoft.com/Forums/en-US/windowssdk/thread/55c40af5-d36c-4dcb-ba7f-e2b9b9a39bc5 for more info.
		DWORD dwBufferSize = sizeof(UNIVERSAL_NAME_INFO) + 1024 * sizeof(wchar_t);
		vector<char> buffer(dwBufferSize);
		wstring resourceName(m_szFileName);
		DWORD status;
		while ((status = WNetGetUniversalName(resourceName.c_str(), UNIVERSAL_NAME_INFO_LEVEL, &buffer[0], &dwBufferSize)) == ERROR_MORE_DATA) {
			buffer.resize(dwBufferSize);
		}

		// If we could interpret the name as a remote name, use the UNC notation instead for the next step
		if (status == NO_ERROR) {
			resourceName = reinterpret_cast<UNIVERSAL_NAME_INFO*>(&buffer[0])->lpUniversalName;
			CChkAss(resourceName.length() < 1024, L"Buffer was overrun!");
		}

		NETRESOURCE nr;
		ZeroMemory(&nr, sizeof(nr));

		nr.dwType = RESOURCETYPE_DISK;
		nr.lpRemoteName = const_cast<wchar_t*>(resourceName.c_str());

		LPTSTR pszSystem = 0;

		while ((status = WNetGetResourceInformation(&nr, &buffer[0], &dwBufferSize, &pszSystem)) == ERROR_MORE_DATA) {
			buffer.resize(dwBufferSize);
		}

		// If we can't get network info, assume local and then check if the volume is readonly. Apparently it's possible to open
		// a file with GENERIC_WRITE on a volume such as a USB-drive that is readonly...
		if (status != NO_ERROR) {
			CFileName fileName(m_szFileName.c_str());

			DWORD dwFileSystemFlags;
			LPCTSTR rootDir = fileName.GetRootDir();
			if (!GetVolumeInformation(rootDir, NULL, 0, NULL, NULL, &dwFileSystemFlags, NULL, 0)) {
				return false;
			}
			return (dwFileSystemFlags & FILE_READ_ONLY_VOLUME) == FILE_READ_ONLY_VOLUME;
		}

		// There appears to be no reasonable way to actually check the 'share permissions' of a network share! NetShareGetInfo at level 2
		// requires begin admin or similar. WMI seems like extreme overkill and will probably just cause a bunch of other problems.
		// since we've at this point in the code actually determined that the file *is* on a network, we fall back to just trying to
		// open it for writing.
		try {
			CFileIO fileTest;
			// Try to open the file with read/write permissions (like we will later) - using the original path.
			fileTest.Open(m_szFileName.c_str(), FALSE, GENERIC_READ | GENERIC_WRITE);
			fileTest.Close();
		}
		catch (TAssert) {
			try {
				CFileIO fileTest;
				// Try to open the file with read permissions instead, to see if that succeeds.
				fileTest.Open(m_szFileName.c_str(), FALSE, GENERIC_READ);
				fileTest.Close();
			}
			catch (TAssert) {
				// If we can't open it read-only either, it's probably a general permissions issue, so
				// we won't just call it read-only but let later code handle it.
				return false;
			}
			return true;
		}
		return false;
	}

	bool IsReadOnly() { return m_isReadOnly; }
	bool IsHidden() { return  (GetAttributes() & FILE_ATTRIBUTE_HIDDEN) != 0; }
	bool SetReadOnly() { return SetAttributes(GetAttributes() | FILE_ATTRIBUTE_READONLY); }
	bool SetHidden() { return SetAttributes(GetAttributes() | FILE_ATTRIBUTE_HIDDEN); }
	bool SetReadWrite() { return SetAttributes(GetAttributes() & ~FILE_ATTRIBUTE_READONLY); }
};
//
//  Helper to handle the case of exceptions in the file-handling command handlers,
//  since it's done the same in all places.
//
static DWORD
HandleCmdException(TAssert& utErr, CCmdParam* pCmdParam, DWORD dwMsgId, const TCHAR* szFileName) {
	// Hide progress window, if any.
	if (pCmdParam->hProgressWnd) {
		SendMessage(GetParent(pCmdParam->hProgressWnd), WM_APP, 0, 0);
	}

	// If it was a cancel we caught, we just show that, otherwise an error message.
	if (utErr.LastError() == WRN_CANCEL) {
		utErr.App(WRN_CANCEL).Show();
	}
	else {
		utErr.File(dwMsgId, szFileName).Show();
	}
	return utErr.LastError();
}

/// \brief Optionally Open/Create a file and/or if necessary present a Save As Dialog
///
/// If putFile is non-NULL, we attempt to open the file in the given mode.
/// If the open fails we present a dialog. If the user insists, we re-try
/// but now always using the CREATE_ALWAYS instead of CREATE_NEW.
///
/// \param putFile Pointer to a CFileIO to open, or NULL - then we just present a dialog.
/// \param fnFile The file name to open/create
/// \param dwOpenMode The FileOpen mode, i.e. OPEN_ALWAYS, CREATE_ALWAYS or CREATE_NEW
/// \param hWnd Owner of the dialog
/// \param fAlwaysAsk Always present the dialog before open.
static void
CreateSaveFile(CFileIO* putFile, CFileName& fnFile, DWORD dwOpenMode, HWND hWnd, bool fAlwaysAsk = false) throw(TAssert) {
	while (true) {
		// Try to open, unless we want to ask first.
		if (fAlwaysAsk) {
			// If the creation failed, display a save-as dialogue, if we're not in server mode.
			CAssert(!CRegistry(HKEY_CURRENT_USER,
				gszAxCryptRegKey,
				szRegValServerMode).GetDword(FALSE)).App(WRN_CANCEL).Throw();

			TCHAR szFileName[MAX_PATH];

			_tcsncpy_s(szFileName, sizeof szFileName / sizeof szFileName[0], fnFile.GetTitle(), MAX_PATH);
			szFileName[MAX_PATH - 1] = _T('\0');
			std::auto_ptr<TCHAR> szDir(_tcsdup(fnFile.GetDir()));

			// Build the filter string, i.e. for example "*.txt\0*.txt\0\0"
			// They don't make it easy by using nul chars...
			TCHAR szFilter[MAX_PATH + MAX_PATH + 3];
			_stprintf_s(szFilter, sizeof szFilter / sizeof szFilter[0], _T("*%s"), fnFile.GetExt());
			_TCHAR* szFilterPart2 = &szFilter[_tcslen(szFilter) + 1];
			_stprintf_s(szFilterPart2, _tcslen(szFilter) + 1, _T("*%s"), fnFile.GetExt());
			szFilterPart2[_tcslen(szFilterPart2) + 1] = _T('\0');

			OPENFILENAME ofn;
			ZeroMemory(&ofn, sizeof ofn);
			ofn.lStructSize = sizeof ofn;
			ofn.hwndOwner = hWnd;
			ofn.lpstrFilter = szFilter;
			ofn.nFilterIndex = 1;
			ofn.lpstrInitialDir = szDir.get();
			ofn.lpstrFile = szFileName;
			ofn.lpstrDefExt = fnFile.GetExt() + 1; // Skip dot
			ofn.nMaxFile = sizeof szFileName / sizeof * szFileName;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOREADONLYRETURN | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;
			if (!GetSaveFileName(&ofn)) {
				CAssert(FALSE).App(WRN_CANCEL).Throw();
			}
			fnFile.Set(ofn.lpstrFile);      // remember the new name we're using instead!

			// If we're not opening, just asking for a new, accept the name provided.
			if (putFile == NULL) {
				return;
			}

			// If we started out with CREATE_NEW, upgrade to CREATE_ALWAYS, now that we've
			// asked the user.
			if (dwOpenMode == CREATE_NEW) {
				dwOpenMode = CREATE_ALWAYS;
			}

			fAlwaysAsk = false;             // Now we do try to open, regardless of the initial situation
		}
		else {
			try {
				// Only try to open, if we're provded with a CFileIO to do it with.
				if (putFile) {
					putFile->Create(fnFile.Get(), TRUE, GENERIC_READ | GENERIC_WRITE, dwOpenMode);
				}
				return;
			}
			catch (TAssert utErr) {
				fAlwaysAsk = true;
			}
		}
	}
}

/// \brief Determine if we're in trial mode
/// \return true if we're in active trial mode
static bool
IsTrial() {
	if (gpTrialMgr) {
		if (gpRestrictMgr) {
			if (gpRestrictMgr->Has(_TT("uses"))) {
				return true;
			}
		}
	}
	return false;
}

/// \brief Enforce trial restrictions - if any
/// If we're expired, show a message box and return true
/// \return false if we're not expired.
static bool
IsExpired() {
	if (IsTrial()) {
		if (gpTrialMgr->Get() >= gpRestrictMgr->GetInt(_TT("uses"))) {
			CMessage cMsg;
			cMsg.AppMsg(WRN_EXPIRED_USES, gpRestrictMgr->GetInt(_TT("uses")));
			cMsg.ShowWarning();
			return true;
		}
	}
	return false;
}

/// \brief Increment the trial counter, if there is one
static void
IncrementTrialCtr() {
	if (IsTrial()) {
		if (gpTrialMgr) {
			gpTrialMgr->Increment();
		}
	}
}

//
//  Expand a wild-card spec, calling the appropriate command handler
//  for every match that is a file. If it's a directory, we walk into
//  that if we're recursing.
//
DWORD
FileExpand(pfCmdT pfCmd, CCmdParam* pCmdParam, const TCHAR* szDir, const TCHAR* szPattern) {
	if (!szDir || !szPattern || !*szPattern) return WRN_IGNORED;

	// Build searchPattern to be 'Directory\*'
	// Must use '*' to find directories to recurse into.
	std::wstring searchPattern = szDir;
	if (searchPattern.length() > 0 && searchPattern[searchPattern.length() - 1] != L'\\') {
		searchPattern += L"\\";
	}
	searchPattern += L"*";

	DWORD dwReturn = 0;
	WIN32_FIND_DATA findData;
	HANDLE hFindFile = FindFirstFile(searchPattern.c_str(), &findData);
	if (hFindFile != INVALID_HANDLE_VALUE) {
		// This is where we collect a list of matching names. We do this because otherwise we
		// may get into infinite loops where we keep rediscovering files that we've for example
		// encrypted already once. The problem of course is that it may require significant amounts
		// of heap memory.
		std::list<std::wstring> listOfFileNames;
		do {
			std::wstring pathAndFilename;
			pathAndFilename = szDir;
			if (pathAndFilename.length() > 0 && pathAndFilename[pathAndFilename.length() - 1] != L'\\') {
				pathAndFilename += L"\\";
			}
			pathAndFilename += findData.cFileName;

			// Now check to see if we found a directory...
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (pCmdParam->fRecurseDir) {
					// If it's not the current directory or the parent...
					if (_tcscmp(findData.cFileName, _T(".")) && _tcscmp(findData.cFileName, _T(".."))) {
						// Now build a search-path for this directory.
						if (dwReturn = FileExpand(pfCmd, pCmdParam, pathAndFilename.c_str(), szPattern)) {
							if (dwReturn != WRN_IGNORED && dwReturn != INF_YESALL) {
								break;
							}
						}
					}
				}
			}
			else if ((findData.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY)) == 0) {
				if (PathMatchSpec(pathAndFilename.c_str(), szPattern)) {
					listOfFileNames.push_back(pathAndFilename);
				}
			}
		} while (FindNextFile(hFindFile, &findData));
		FindClose(hFindFile);
		while (!listOfFileNames.empty()) {
			// We overwrite the file-name param, but that should not matter. If needed,
			// we can always save it here and restore after the Cmd-call.
			pCmdParam->szParam1 = listOfFileNames.front();
			listOfFileNames.pop_front();
			if (dwReturn = (*pfCmd)(pCmdParam)) {
				if (dwReturn != WRN_IGNORED && dwReturn != INF_YESALL) {
					break;
				}
			}
		}
	}
	return dwReturn;
}

/// \brief Check if a given files path is in, or below, a given folder
/// \param szFile the full pathname to the file
/// \param szFolder the full path to the folder (or NULL)
/// \return true if the files path is in the folder (if any was given)
static bool
IsInFolder(LPCTSTR szFile, LPCTSTR szFolder) {
	if (szFile == NULL || szFolder == NULL) {
		return false;
	}

	TCHAR szShortFile[MAX_PATH];
	TCHAR szShortFolder[MAX_PATH];

	GetShortPathName(szFolder, szShortFolder, sizeof szShortFolder / sizeof szShortFolder[0]);
	GetShortPathName(szFile, szShortFile, sizeof szShortFile / sizeof szShortFile[0]);

	return _tcsnicmp(szShortFile, szShortFolder, _tcslen(szShortFolder)) == 0;
}

/// \brief Check if a given path represents an encrypted file.
/// \param szPath The full path to an existing file.
/// \return true if the file appears to be a valid encrypted file.
static bool
IsEncrypted(LPCTSTR szPath) {
	CFileIO fioPlain;
	bool fIsEncrypted = true;
	fioPlain.Open(szPath, FALSE, GENERIC_READ, FILE_SHARE_READ);
	try {
		CHeaders Headers;
		Headers.VerifyStructure(fioPlain);
	}
	catch (TAssert utErr) {
		fIsEncrypted = false;
	}
	return fIsEncrypted;
}

//
//  Encrypt and compress a file, but leave the original.
//
//  Return 0 on success, error code otherwise
//
//  "Primary Execute Request Thread"
//
DWORD
CmdEncryptZCFile(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	DWORD dwReturn = 0;
	try {
		CFileName fnPlain;
		fnPlain.Set(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str());

		// In server-mode we allow most things, including encrypting system files...
		if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
			// Check if this file appears to be in the Windows folder or the Program Files folder
			// as this is usually a bad indication.
			TCHAR szSystemRoot[_MAX_PATH];
			szSystemRoot[0] = _T('\0');
			TCHAR szWindir[_MAX_PATH];
			szWindir[0] = _T('\0');
			TCHAR szProgramFiles[_MAX_PATH];
			szProgramFiles[0] = _T('\0');

			size_t ccRequired;

			_tgetenv_s(&ccRequired, szSystemRoot, sizeof szSystemRoot / sizeof szSystemRoot[0], _T("SystemRoot"));
			_tgetenv_s(&ccRequired, szWindir, sizeof szWindir / sizeof szWindir[0], _T("windir"));
			_tgetenv_s(&ccRequired, szProgramFiles, sizeof szProgramFiles / sizeof szProgramFiles[0], _T("ProgramFiles"));

			if (IsInFolder(fnPlain.Get(), szSystemRoot) || IsInFolder(fnPlain.Get(), szWindir) || IsInFolder(fnPlain.Get(), szProgramFiles)) {
				// Give a warning that it appears that the user is about to encrypt a file in a bad folder
				CRegistry utRegWarn(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSystemFolderWarn);
				BOOL fNotAgain = utRegWarn.GetDword(FALSE);
				// ...unless we've already been told not to issue this warning!
				if (!fNotAgain) {
					bool fOk = WarningDlg(_T(""), INF_SYSTEM_FOLDER_WARN, INF_DONTREPEAT, fNotAgain);
					if (fNotAgain) {
						utRegWarn.SetDword(fNotAgain);
					}
					// If this was not OK, let user try again
					if (!fOk) {
						return WRN_CANCEL;
					}
				}
			}
		}

		// If we should igore already encrypted content...
		if (pCmdParam->fIgnoreEncrypted) {
			if (IsEncrypted(fnPlain.Get())) {
				return WRN_IGNORED;
			}
		}

		if (IsExpired()) {
			return WRN_CANCEL;
		}

		CKeyPrompt utKeyPrompt; // we need this for the duration
		CCryptoKey* pCryptoKey = pgKeyList->FindEncKey(pCmdParam->dwBatch);
		TKey* pKey = NULL;
		if (pCryptoKey != NULL) {
			pKey = pCryptoKey->Key();
		}
		// If no default encryption key
		if (pKey == NULL) {
			// We know that hProgressWnd is part of a dialogue, and thus the parent of that
			// is what we want to have has parent for the pass phrase dialogue. This is not
			// neat, it's ugly, but the whole window handling needs massive clean-up anyway.
			utKeyPrompt.New(GetParent(GetParent(pCmdParam->hProgressWnd)));
			// If the user entered a key, and did not cancel
			if (utKeyPrompt.Get() != NULL) {
				// Test if we really should save the key here.
				BOOL fSaveEncKey = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveEncKey).GetDword();
				if (fSaveEncKey || pCmdParam->dwBatch != 0) {
					// This is may be a permanent allocation here.
					HEAP_CHECK_BEGIN(_T("CmdEncryptZCFile(a)"), TRUE);
					pKey = pgKeyList->AddEncKey(utKeyPrompt.Get(), fSaveEncKey ? 0 : pCmdParam->dwBatch)->Key();
					HEAP_CHECK_END
				}
				else {
					pKey = utKeyPrompt.Get();
				}
				BOOL fSaveDecKey = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveDecKey).GetDword(FALSE);
				if (fSaveDecKey || pCmdParam->dwBatch != 0) {
					pgKeyList->AddKey(utKeyPrompt.Get(), FALSE, fSaveDecKey ? 0 : pCmdParam->dwBatch);
				}
			}
			else {
				dwReturn = WRN_CANCEL;
			}
		}

		HEAP_CHECK_BEGIN(_T("CmdEncryptZCFile(b)"), 0)
			if (pKey != NULL) {
				// Either use the given output name, or derive one.
				CFileName fnCipher;
				fnCipher.Set(pCmdParam->szParam1.c_str());
				fnCipher.DashExt().AddExt((LPTSTR)gszAxCryptFileExt);
				if (!pCmdParam->szParam2.empty()) {
					fnCipher.Override(pCmdParam->szParam2.c_str());
				}

				CFileIO utFilePlain, utFileCipher;
				// Open plain-text
				utFilePlain.Open(fnPlain.Get(), FALSE, GENERIC_READ, FILE_SHARE_READ);

				// Try to open cipher-text. If we can't for example due to existance etc, show dlg
				fnCipher.SetCurDir(pCmdParam->szCurDir.c_str());
				CreateSaveFile(&utFileCipher, fnCipher, pCmdParam->fAppend ? OPEN_ALWAYS : CREATE_NEW, GetForegroundWindow());

				HEAP_CHECK_BEGIN(_T("CmdEncryptZCFile(c)"), 0)
					CHeaders utHeaders;
				utHeaders.SetDataEncKey(pKey);
				utHeaders.SetFileName(CFileName(pCmdParam->szParam1.c_str()).GetTitle());
				utHeaders.SetFileTimes(utFilePlain.GetFileTimes());

				// Store a given id-tag into the headers, in the clear.
				if (!pCmdParam->szIdTag.empty()) {
					utHeaders.SetIdTag(pCmdParam->szIdTag.c_str());
				}

				HEAP_CHECK_BEGIN(_T("CmdEncryptZCFile(d)"), 0)
					// See [ 1692597 ] GUID error using XP synchronize, there appears to be some kind of case where the file
					// is not properly rewound. So we'll safety first rewind here.
					if (!pCmdParam->fAppend) {
						utFileCipher.SetFilePointer(0);
						utFileCipher.SetEndOfFile();
					}
				CWrapper utWrap(&utHeaders, pCmdParam->hProgressWnd);
				utWrap.Wrap(utFilePlain, utFileCipher, pCmdParam->nWipePasses, pCmdParam->fSlowSafe);
				HEAP_CHECK_END
					HEAP_CHECK_END

					utFileCipher.Close(TRUE);			// Close and force keep

					// Set encrypted file-times to plain-file times, if the default from 1.5.2.2 has changed.
				if (CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValKeepTimeStamp).GetDword() != 0) {
					// Re-open after close and flush to set proper file-times.
					utFileCipher.Open(fnCipher.Get(), FALSE, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE);
					utFileCipher.SetFileTimes(utFilePlain.GetFileTimes());    // Set the encrypted file-times as the plain
					utFileCipher.Close();
				}

				utFilePlain.Close();

				// Set the encrypted read-only, if the plain file is too, and we can affect the cipher-file.
				CReadOnlyMgr utPlainROM(fnPlain.Get()), utCipherROM(fnCipher.Get());
				if (utPlainROM.IsReadOnly()) {
					utCipherROM.SetReadOnly();  // Fail silently on 'expected' errors.
				}

				// Set the encrypted hidden, if the plain file is too.
				if (utPlainROM.IsHidden()) {
					utCipherROM.SetHidden();
				}

				SHChangeNotify(SHCNE_CREATE, SHCNF_PATH, fnCipher.Get(), NULL);

				// CmdEncryptZCFile: If we got this far, increment the trial counter - if we have one.
				IncrementTrialCtr();
			}
			else {
				dwReturn = WRN_CANCEL;
			}
		HEAP_CHECK_END
	}
	catch (TAssert utErr) {
		// No error message on simple cancel request.
		if (utErr.LastError() == WRN_CANCEL) {
			return utErr.LastError();
		}
		dwReturn = HandleCmdException(utErr, pCmdParam, MSG_WRAP_ERROR, pCmdParam->szParam1.c_str());
	}
	return dwReturn;
}

class CSinkFoundSync : public AxPipe::CSink {
public:
	// If we ever get here - we found data after a sync!
	void Out(AxPipe::CSeg* pSeg) {
		pSeg->Release();
		SetError(AxPipe::ERROR_CODE_DERIVED, _T(""));
	}
};

class CPipeLimitData : public AxPipe::CPipe {
	size_t lMax, lRead;

public:
	CPipeLimitData() {
		lRead = 0;
		lMax = 1024 * 1024;   // Allow for debug-versions of the selfdecryptor size as well
	}

protected:
	void Out(AxPipe::CSeg* pSeg) {
		size_t lThisSeg = lRead + pSeg->Len() > lMax ? lMax - lRead : pSeg->Len();
		pSeg->Len(lThisSeg);
		Pump(pSeg);
		lRead += lThisSeg;

		if (!GetErrorCode() && (lRead == lMax)) {
			SetError(AxPipe::ERROR_CODE_DERIVED + 1, _T(""));
		}
	}
};

/// \brief Test if a file is a Xecrets File SFX-file
/// Do some heuristic tests to determine if it's an Xecrets File SFX-file. These are
/// not perfect currently, but should serve. Currently, the critera that has to
/// met are:
/// 1 - The file name ends with .exe
/// 2 - Is a Windows Executable
/// 3 - The Xecrets File GUID appears within the first 256K
/// Additional tests should actually validate the structure of the headers and
/// data as well, but for currently we don't.
/// \param szFileName The full path or relative to current directory of the file
/// \return true if it appears to be an Xecrets File SFX-file
static bool
IsAlreadySfx(const _TCHAR* szFileName) {
	// We probably don't need a sfi, for this call, but the docs are unclear.
	SHFILEINFO sfi;
	ZeroMemory(&sfi, sizeof sfi);
	// We use SHGetFileInfo rather than GetBinaryType to work on Win9x.
	if ((_tcsnicmp(PathFindExtension(szFileName), _T(".exe"), 4) == 0) && SHGetFileInfo(szFileName, 0, &sfi, sizeof sfi, SHGFI_EXETYPE) != 0) {
		// Ok, it's an executable. Now see if it contains the GUID
		AxPipe::CSourceMemFile In;

		In.Append(new CPipeLimitData);
		In.Append((new AxPipe::Stock::CPipeFindSync)->Init(&guidAxCryptFileId, sizeof guidAxCryptFileId));
		In.Append(new CSinkFoundSync);
		In.Init(szFileName);

		// Run the input through the pipe...
		int iErrorCode = In.Open()->Drain()->Close()->Plug()->GetErrorCode();

		if (iErrorCode == AxPipe::ERROR_CODE_DERIVED) {
			return true;
		}
	}
	return false;
}
//
//  Encrypt and compress a file to a new SFX, and leave the original.
//  First we generate the output name, unless it's already given.
//  Then we copy the selfdecrypting .exe to that
//  Finally, we encrypt and append to that.
//
//  Return 0 on success, error code otherwise
//
//  "Primary Execute Request Thread"
//
DWORD
CmdSfxEncNewFile(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	// If we're supposed to ignore encrypted and it appears to be one,
	// just return as if we're done.
	if (pCmdParam->fIgnoreEncrypted && (IsEncrypted(pCmdParam->szParam1.c_str()) || IsAlreadySfx(pCmdParam->szParam1.c_str()))) {
		return 0;
	}

	if (IsExpired()) {
		return WRN_CANCEL;
	}

	// Use a local copy.
	CCmdParam cmdParam = *pCmdParam;
	try {
		// If we don't have a specific output-name set, we remove a
		// possible .xxx extension, and then add a .exe.
		if (cmdParam.szParam2.empty()) {
			CFileName fnOutput(cmdParam.szParam1.c_str());
			if (_tcscmp(fnOutput.GetExt(), gszAxCryptFileExt) == 0) {
				fnOutput.DelExt();
			}
			else {
				fnOutput.DashExt();
			}
			fnOutput.AddExt(_T(".exe"));
			cmdParam.szParam2 = fnOutput.Get();
		}

		// Get the full resulting name, the same way that the encrypt will.
		CFileName fnSfx(cmdParam.szParam1.c_str());
		if (!cmdParam.szParam2.empty()) {
			fnSfx.Override(cmdParam.szParam2.c_str());
		}

		// Check if the file exists at all first
		if (GetFileAttributes(fnSfx.Get()) != INVALID_FILE_ATTRIBUTES) {
			// If it does, then ask first if we're about to overwrite.
			CreateSaveFile(NULL, fnSfx, 0, GetForegroundWindow(), true);
		}
		else {
			// Ensure that it's just a case of a missing file.
			CAssert((GetLastError() == ERROR_FILE_NOT_FOUND)).Sys().Throw();
		}

		// Build the path of the self extractor to start with
		CFileName fnSfxExe;
		fnSfxExe.SetPath2ExeName().SetTitle((LPTSTR)gszAxCryptSfxName);

		// Get the first part, the self extractor, in place.
		CAssert(CopyFile(fnSfxExe.Get(), fnSfx.Get(), FALSE)).Sys(MSG_SYSTEM_CALL, _T("CmdSfxEncNewFile() [CopyFile()]")).Throw();

		// Now, ensure that the file is not marked as read-only, as it will be if the AxDecrypt comes from a CD-ROM for example
		DWORD dwAttrib = GetFileAttributes(fnSfx.Get());
		if (dwAttrib & FILE_ATTRIBUTE_READONLY) {
			CAssert(SetFileAttributes(fnSfx.Get(), dwAttrib & ~FILE_ATTRIBUTE_READONLY)).Sys(MSG_SYSTEM_CALL, _T("CmdSfxEncNewFile() [SetFileAttributes()]")).Throw();
		}

		// Now simply encrypt a copy and append to the requested output
		cmdParam.fAppend = TRUE;

		// Set the real, resulting, name of the output for the encryption, in case it was changed.
		cmdParam.szParam2 = fnSfx.Get();
		DWORD dwReturn = CmdEncryptZCFile(&cmdParam);
		if (dwReturn) {
			(void)DeleteFile(fnSfx.Get());
			CAssert(FALSE, dwReturn).Throw();
		}
		// CmdSfxEncNewFile: This counts
		IncrementTrialCtr();
	}
	catch (TAssert utErr) {
		// No error message on simple cancel request.
		if (utErr.LastError() == WRN_CANCEL) {
			return utErr.LastError();
		}
		return HandleCmdException(utErr, pCmdParam, MSG_WRAP_ERROR, pCmdParam->szParam1.c_str());
	}
	return 0;
}

//
// Encrypt the file to name concatenated with the extension,
// Wipe and delete the orignal.
//
//	Return 0 on success, error code otherwise.
//
// "Primary Execute Request Thread"
//
DWORD
CmdEncryptZFile(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	// If necessary, set current directory
	CFileName fnPlain;
	fnPlain.Set(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str());

	// Start by checking the read-only status of the plain-text.
	CReadOnlyMgr utPlainROM(fnPlain.Get());

	DWORD dwReturn;
	try {
		// ..and by ensuring writeability, as we're intending to wipe it!
		utPlainROM.AssWriteable();

		dwReturn = CmdEncryptZCFile(pCmdParam);
		if (dwReturn || dwReturn == WRN_IGNORED) {
			return dwReturn;
		}

		// If the original was read-only, we now need to remove that to enable wiping, if we can.
		if (!utPlainROM.IsReadOnly() || utPlainROM.SetReadWrite()) {
			if (pCmdParam->fSlowSafe) {
				// Since it's a plain-text, we wipe it with the real wiper.
				dwReturn = CmdWipeSilent(pCmdParam);
			}
			else {
				// Just delete it
				CFileIO utFilePlain;
				utFilePlain.Create(fnPlain.Get(), TRUE, GENERIC_READ | GENERIC_WRITE, CREATE_ALWAYS);
				utFilePlain.Close();				// Close (and delete)
			}
		}
	}
	catch (TAssert utErr) {
		dwReturn = HandleCmdException(utErr, pCmdParam, MSG_WRAP_ERROR, fnPlain.GetTitle());
	}
	return dwReturn;
}
//
//	Helper to first look in key cache, and then prompt for key if that
//	did not work.
//
//	Return TRUE on opened headers, FALSE on user cancel.
//	Throws CAssert exception error.
//
//  The Key-encrypting-key is returned in *ppKeyEncKey, and must be deleted
//  by caller.
//
static BOOL
TryCacheAndPromptOpen(CHeaders* pHeaders, TKey** ppKeyEncKey, DWORD dwBatch, LPCTSTR szFileName, HWND hProgressWnd) {
	if (pgKeyList->TryOpen(pHeaders, ppKeyEncKey, dwBatch)) {
		return TRUE;
	}

	CKeyPrompt utPromptKey;
	// We know that hProgressWnd is part of a dialogue, and thus the parent of that
	// is what we want to have has parent for the pass phrase dialogue. This is not
	// neat, it's ugly, but the whole window handling needs massive clean-up anyway.
	utPromptKey.Old(INF_ENTER_PASS, szFileName, GetParent(GetParent(hProgressWnd)));
	while (utPromptKey.Get() != NULL) {
		if (pHeaders->Open(utPromptKey.Get())) {
			// Test if we really should save the key here.
			BOOL fSaveEncKey = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveEncKey).GetDword();
			if (fSaveEncKey || dwBatch != 0) {
				// This is may be a permanent allocation here.
				HEAP_CHECK_BEGIN(_T("TryCacheAndPromptOpen"), TRUE);
				pgKeyList->AddEncKey(utPromptKey.Get(), fSaveEncKey ? 0 : dwBatch)->Key();
				HEAP_CHECK_END
			}
			BOOL fSaveDecKey = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveDecKey).GetDword(FALSE);
			if (fSaveDecKey || dwBatch != 0) {
				pgKeyList->AddKey(utPromptKey.Get(), FALSE, fSaveDecKey ? 0 : dwBatch);
			}
			*ppKeyEncKey = new TKey(*utPromptKey.Get());
			ASSPTR(*ppKeyEncKey);

			return TRUE;
		}
		MessageBeep(MB_OK);
		// We know that hProgressWnd is part of a dialogue, and thus the parent of that
		// is what we want to have has parent for the pass phrase dialogue. This is not
		// neat, it's ugly, but the whole window handling needs massive clean-up anyway.
		utPromptKey.Old(INF_REENTER_PASS, szFileName, GetParent(GetParent(hProgressWnd)));
	}
	return FALSE;
}
//
// Decrypt a file. Retain the original.
//
DWORD
CmdDecryptCFile(CCmdParam* pCmdParam) {
	bool fTryBrokenFile = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValTryBrokenFile).GetDword(FALSE) == TRUE;

	if (pCmdParam->szParam1.empty()) {
		return ERROR_SUCCESS;
	}

	DWORD dwReturn = ERROR_SUCCESS;

	// If necessary, set current directory
	CFileName fnCipher;
	fnCipher.Set(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str());

	HEAP_CHECK_BEGIN(_T("CmdDecryptFile"), 0);
	try {
		// If not overridden, verify that the file has the correct extension
		if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValAllowAnyExtension).GetDword(FALSE)) {
			CAssert(_tcsicmp(fnCipher.GetExt(), gszAxCryptFileExt) == 0).App(MSG_INVALID_EXT).Throw();
		}

		CFileIO utFileCipher, utFilePlain;
		CHeaders utHeaders;
		CWrapper utWrap(&utHeaders, pCmdParam->hProgressWnd);

		utFileCipher.Open(fnCipher.Get(), FALSE, GENERIC_READ, FILE_SHARE_READ);

		utHeaders.Load(utFileCipher);

		CPtrTo<TKey> pKeyEncKey;
		if (TryCacheAndPromptOpen(&utHeaders, &pKeyEncKey, pCmdParam->dwBatch, fnCipher.GetTitle(), pCmdParam->hProgressWnd)) {
			// Either use the given output name, or
			// Get the real original name from the headers
			CFileName fnPlain;
			fnPlain.Set(pCmdParam->szParam1.c_str());
			fnPlain.SetTitle(utHeaders.GetFileName());
			if (!pCmdParam->szParam2.empty()) {
				fnPlain.Override(pCmdParam->szParam2.c_str());
			}
			fnPlain.SetCurDir(pCmdParam->szCurDir.c_str());

			// Try to create it. If it fails, present a dialoge
			CreateSaveFile(&utFilePlain, fnPlain, CREATE_NEW, GetForegroundWindow());

			// Keep the file in all cases if we're in recover mode
			if (fTryBrokenFile) {
				utFilePlain.SetDelete(FALSE);
			}

			HEAP_CHECK_BEGIN(_T("CmdDecryptFile(a)"), 0);
			// Now we have open headers to work with!
			CWrapper utUnwrap(&utHeaders, pCmdParam->hProgressWnd);
			utUnwrap.Unwrap(utFileCipher, utFilePlain, pCmdParam->nWipePasses, pCmdParam->fSlowSafe);
			HEAP_CHECK_END

				// Restore the old file times, first close and then re-open
				utFilePlain.Close(TRUE);			// Override delete-on-close
			utFilePlain.Open(fnPlain.Get(), FALSE, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE);
			utFilePlain.SetFileTimes(utHeaders.GetFileTimes());
			utFileCipher.Close();				// Close (and retain)

			// Set the original read-only, if the encrypted file is too.
			CReadOnlyMgr utCipherROM(fnCipher.Get()), utPlainROM(fnPlain.Get());
			if (utCipherROM.IsReadOnly()) {
				utPlainROM.SetReadOnly();
			}

			// Also set the original hidden, if the encrypted file was too
			if (utCipherROM.IsHidden()) {
				utPlainROM.SetHidden();
			}

			SHChangeNotify(SHCNE_CREATE, SHCNF_PATH, fnPlain.Get(), NULL);
		}
		else {
			if (CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
				return ERR_NO_PASSPHRASE;
			}
			else {
				return WRN_CANCEL;
			}
		}
	}
	catch (TAssert utErr) {
		// No error message on simple cancel request.
		if (utErr.LastError() == WRN_CANCEL) {
			return utErr.LastError();
		}
		dwReturn = HandleCmdException(utErr, pCmdParam, MSG_UNWRAP_ERROR, fnCipher.GetTitle());
	}
	return dwReturn;	// Success!
	HEAP_CHECK_END
}
//
//  Decrypt a file, and wipe the original
//
DWORD
CmdDecryptFile(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	DWORD dwReturn = CmdDecryptCFile(pCmdParam);
	if (dwReturn) return dwReturn;

	// Build fully qualified path, using file-name parameter and current directory.
	CFileName fnCipher;
	fnCipher.Set(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str());
	try {
		CReadOnlyMgr utCipherROM(fnCipher.Get());

		// Throw an exception if not writeable
		utCipherROM.AssWriteable();

		// If the source was read-only, we try to wipe it, removing read-only if necessary and possible
		if (!utCipherROM.IsReadOnly() || utCipherROM.SetReadWrite()) {
			// Since it's a cipher-file, we just wipe the initial part to be a little faster.
			CFileIO utFileCipher;
			if (pCmdParam->fSlowSafe) {
				utFileCipher.Open(fnCipher.Get(), TRUE, GENERIC_READ | GENERIC_WRITE);
				utFileCipher.WipeShort();			// Just wipe the first 512 bytes of the cipher text file.
			}
			else {
				utFileCipher.Create(fnCipher.Get(), TRUE, GENERIC_READ | GENERIC_WRITE, CREATE_ALWAYS);
			}
			utFileCipher.Close();				// Close (and delete)
			SHChangeNotify(SHCNE_DELETE, SHCNF_PATH, fnCipher.Get(), NULL);
		}
	}
	catch (TAssert utErr) {
		dwReturn = HandleCmdException(utErr, pCmdParam, MSG_WRAP_ERROR, fnCipher.GetTitle());
	}
	return dwReturn;
}
//
//	Test to see if a file is locked. Non-existence is treated as locked, we assume
//	the reason is that the application is busy doing things to it, and that it will
//	reappear soon... The most likely reason is a save by the application.
//
static BOOL
IsFileLocked(LPCTSTR szFileName) {
	// Now attempt to open the file - Lets try to get ahead of the competition to avoid conflict
	// by increasing the priority for a short while.
	int iThreadPrio = GetThreadPriority(GetCurrentThread);
	(void)SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
	HANDLE hFile = CreateFile(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	DWORD dwLastError = GetLastError();
	if (hFile != INVALID_HANDLE_VALUE) (void)CloseHandle(hFile);
	(void)SetThreadPriority(GetCurrentThread(), iThreadPrio);

	if (hFile == INVALID_HANDLE_VALUE) {
		switch (dwLastError) {
		case ERROR_FILE_NOT_FOUND:
		case ERROR_SHARING_VIOLATION:
		case ERROR_ACCESS_DENIED:	// More and more magic... We've seen this reported too...
			return TRUE;
		default:
			SetLastError(dwLastError);
			CAssert(FALSE).Sys(MSG_SYSTEM_CALL, _T("CreateFile() [IsFileLocked()]")).Throw();
		}
	}
	return FALSE;
}

//
//	Wait for a file to become closed, assuming it will be opened in a non-shareable
//	way.
//
//	First Wait for it to become locked a given maximum milliseconds,
//	in increments of given milliseconds.
//
//	Return TRUE if we have determined that the file really was locked, and was locked for at least dwMinLockTime and is now released.
//
static BOOL
WaitForLockThenUnlock(LPCTSTR szFileName, DWORD dwMaxWaitForLock, DWORD dwIncrement, DWORD dwMinTimeLocked) {
	CHChange hChangeNotification;		// Auto-close on exception etc.
	dwMaxWaitForLock -= dwMaxWaitForLock % dwIncrement;		// Ensure even multiple of increments
	const DWORD dwRelockWait = 500, dwRelockIncrement = 100, dwPollWait = 100;
	DWORD dwStart = GetTickCount();
	// First see if it actually will become locked...
	do {
		// If it has become locked for the first time...
		if (IsFileLocked(szFileName)) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("WaitForLockThenUnlock: [The file is locked for the first time]"), szFileName).LogEvent(3);
			hChangeNotification = FindFirstChangeNotification(CFileName(szFileName).GetDir(), FALSE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_LAST_WRITE);
			// For reasons unknown, there appears to be situations (the documented case is Win95 word launched via
			// outlook) where FFCN doesn't find the directory of the file. Since this is kind of non-critical
			// anyway, let's be a bit permissive here.
			// CAssert(hChangeNotification.IsValid()).Sys(MSG_SYSTEM_CALL, _T("FindFirstChangeNotification() [WaitForLockThenUnlock()]")).Throw();
			if (!hChangeNotification.IsValid()) {
				CMessage().Wrap(0).AppMsg(MSG_SYSTEM_CALL, CMessage().SysMsg(GetLastError()).GetMsg(), _T("FindFirstChangeNotification() [WaitForLockThenUnlock()]")).LogEvent(1);
			}

			int i;
			do {
				do {
					// We trust that we will see change notifications, but in some cases we will not,
					// thus we test every 1/10th of a second.
					if (hChangeNotification.IsValid()) {
						DWORD dwWaitResult = WaitForSingleObjectEx(hChangeNotification, 100, FALSE);
						// If a change notification was received...
						if (dwWaitResult == WAIT_OBJECT_0) {
							CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("WaitForLockThenUnlock: [A change notification was received]"), szFileName).LogEvent(3);
							CAssert(FindNextChangeNotification(hChangeNotification) || (GetLastError() == ERROR_NO_MORE_FILES)).Sys(MSG_SYSTEM_CALL, _T("FindNextChangeNotification() [WaitForLockThenUnlock()]")).Throw();
							// If we get a change notification, we need to yield control a bit more to the application so it can finish what it's doing, otherwise
							// we may end up locking the file for the application causing an error. There also seems to be bad interaction with Avast. [2975138]
							Sleep(dwPollWait);
						}
						else {
							// ... otherwise assert that it was a timeout, not an error.
							CAssert(dwWaitResult == WAIT_TIMEOUT).Sys(MSG_SYSTEM_CALL, _T("WaitForSingleObjectEx() [WaitForLockThenUnlock()]")).Throw();
							CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("WaitForLockThenUnlock: [A timeout occurred]"), szFileName).LogEvent(4);
						}
					}
					else {
						Sleep(dwPollWait);
					}
					// Notification or timeout - check if file still locked.
				} while (IsFileLocked(szFileName));
				// Wait for up to 1/2 second for the file to become re-locked.
				for (i = dwRelockWait; i > 0; i -= dwRelockIncrement) {
					// First we give the other app a chance to re-lock, if it is just a save. This is really far from perfect...
					Sleep(dwRelockIncrement);	// 1/10th of a second should be enough in most cases, actually the important thing is to yield control
					if (IsFileLocked(szFileName)) break;
				}
				// re-start wait unless we have waited a bit and the file is still free.
			} while (i > 0);
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("WaitForLockThenUnlock: [Now it has remaind unlocked long enough]"), szFileName).LogEvent(3);
			// Now it has remained unlocked long enough
			if (hChangeNotification.IsValid()) {
				CAssert(hChangeNotification.Close()).Sys(MSG_SYSTEM_CALL, _T("CloseHandle(hChangeNotification) [WaitForLockThenUnlock()]")).Throw();
			}

			// Return TRUE if the file was locked long enough (including the unlocked delay), otherwise false.
			// This will not work if the file was locked for more the 49.7 days or so due to wraparound
			return (GetTickCount() - dwStart) >= (dwMinTimeLocked + dwRelockWait);
			// ... still not locked for the first time - if we should wait more, sleep and decrement.
		}
		else if (dwMaxWaitForLock) {
			Sleep(dwIncrement);
			dwMaxWaitForLock -= dwIncrement;
		}
	} while (dwMaxWaitForLock);
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("WaitForLockThenUnlock: [It was never detected as locked]"), szFileName).LogEvent(3);
	return FALSE;
}
/// \brief Check if a file is classed as a temporary file
/// \param szPath A path or a file name
/// \return true if the name appears to represent a temporary
static bool
IsTempFile(const TCHAR* szPath) {
	TCHAR* szFileTitle = PathFindFileName(szPath);

	if (PathMatchSpec(szFileTitle, _T("*.tmp"))) return true;
	if (PathMatchSpec(szFileTitle, _T("*.bak"))) return true;
	if (PathMatchSpec(szFileTitle, _T("~*.*"))) return true;
	return false;
}

/// \brief Check if a directory only contains the given file - or at least no others.
/// We scan a directory for files, returning false if any other files or directories
/// than the one passas as param szFile is returned. We return true if the directory
/// is empty too, the important part is that no other files are there.
/// \param szPath The full path to the file
/// \return true if no other files or directories were found
static bool
OnlyThisFileInDir(const TCHAR* szPath) {
	// We do this by doing two searches, that way we are less dependent on various
	// strategies for naming files in Windows.
	WIN32_FIND_DATA findData;
	HANDLE hFindFile;
	if ((hFindFile = FindFirstFile(szPath, &findData)) != INVALID_HANDLE_VALUE) {
		int cfFile = 0;
		do {
			if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
				cfFile++;
			}
		} while (FindNextFile(hFindFile, &findData));
		FindClose(hFindFile);

		// The length calculation is ok, since we're replacing the file name spec
		// with a '*' which is only one TCHAR - any file name will have to be at
		// least that long.
		size_t ccSearchPattern = _tcslen(szPath) + 1;
		std::auto_ptr<TCHAR> szSearchPattern(new TCHAR[ccSearchPattern]);
		ASSPTR(szSearchPattern.get());

		// Build szSearchPattern to be 'Directory\*'
		_tcscpy_s(szSearchPattern.get(), ccSearchPattern, szPath);
		PathRemoveFileSpec(szSearchPattern.get());
		PathAppend(szSearchPattern.get(), _T("*"));

		if ((hFindFile = FindFirstFile(szSearchPattern.get(), &findData)) != INVALID_HANDLE_VALUE) {
			int cfAll = 0;
			do {
				// Here we only not count the special directory entry files - all others count, even directories
				if (_tcscmp(findData.cFileName, _T(".")) && _tcscmp(findData.cFileName, _T(".."))) {
					// We don't count what we feel sure to be temp-files
					if (!IsTempFile(findData.cFileName)) {
						cfAll++;
					}
				}
			} while (FindNextFile(hFindFile, &findData));
			FindClose(hFindFile);

			// If we found exactly the same number of files as '*' as 'File' - Then no extras!
			return cfFile == cfAll;
		}
	}
	// One or the other searches failed - we treat this as suspicious, thus false
	return false;
}
//
//  Small helper to determine if a file is a 16-bit executable file. Since this is a special
//  case for the code using it, we're trying to positively determine if it is a 16-bit, instead
//  of trying for 'not 32-bit'. That way we're presumably more forward compatible for new formats,
//  which will not be recognized as 16-bit thus.
//
//  For references to similar code, search MSDN or the net for e_lfanew.
//
/*
static bool
Is16BitExe(const TCHAR *szFileName) {
	bool fIs16BitExe = false;
	HANDLE hFile;
	if ((hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) {
		HANDLE hFileMapping;
		if (hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL)) {
			void * pView;
			if (pView = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0)) {
				if (((PIMAGE_DOS_HEADER)pView)->e_magic == IMAGE_DOS_SIGNATURE) {
					DWORD dwSignature = *(PDWORD)((DWORD)pView + ((PIMAGE_DOS_HEADER)pView)->e_lfanew);
					if (dwSignature != IMAGE_NT_SIGNATURE) {
						if ((LOWORD(dwSignature) == IMAGE_OS2_SIGNATURE) || (LOWORD(dwSignature) == IMAGE_DOS_SIGNATURE)) {
							fIs16BitExe = true;
						}
					}
				}
				UnmapViewOfFile(pView);
			}
			CloseHandle(hFileMapping);
		}
		CloseHandle(hFile);
	}
	return fIs16BitExe;
}
*/
//
//  Helper to launch. I'm not using ShellExecute(Ex) because I ran into problems
//  on Win98 in some configuration. Was probably not really my code's problem,
//  but this gives me better control over the process anyway...
//  ...but it turns out it's too complex to emulate ShellExecute in all it's
//  glory, so we're back to using ShellExecute again...
//
//  The directory to use is tricky. Ideally, one would want to have the original
//  plain text file directory as current and default for save-as etc. Problem is
//  the Save As-common dialoge has a different view of things... In the end, it
//  seems hard to avoid saves to the directory where the opened file resides. As we
//  want this to be temp-directory under our control it's basically hopeless, so we'll
//  just have to handle saves to the temp-directory. This is the callers job though.
//
//  Although we do pass the plain text directory here, we just pass it to ShellExec, waiting
//  for wisdom to arrive.
//
static bool
MyShellExecute(const TCHAR* szDocumentName, const TCHAR* szDir, const TCHAR* szApp2Use = NULL) {
	SHELLEXECUTEINFO sei;
	ZeroMemory(&sei, sizeof sei);

	sei.cbSize = sizeof sei;
	sei.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOCLOSEPROCESS;
	sei.lpVerb = NULL; // It turns out this: _T("open"); is not quite universal... Some apps have invented their own verbs, notably Visual Studio!!!

	// If we think we know the app to use, provide it instead, and pass the file
	// as a parameter.
	if (szApp2Use && szApp2Use[0]) {
		sei.lpFile = szApp2Use;
		sei.lpParameters = szDocumentName;
	}
	else {
		sei.lpFile = szDocumentName;
	}
	sei.lpDirectory = szDir;
	sei.nShow = SW_SHOWNORMAL;

	if (ShellExecuteEx(&sei)) {
		if (sei.hProcess) {
			WaitForInputIdle(sei.hProcess, 1000);
			// Close the handles - we don't need them right now. The reason I don't use this info
			// to determine the child process is because it's not always the process we launch that
			// actually does the work...
			CAssert(CloseHandle(sei.hProcess)).Sys(MSG_SYSTEM_CALL, _T("CloseHandle(sei.hProcess) [MyShellExecute()]")).Throw();
		}
		return true;
	}
	return false;

	/*
		TCHAR szExec[MAX_PATH];

		DWORD dwRet;
		if((dwRet = (DWORD)FindExecutable(szDocumentName, NULL, szExec)) > 32) {
			// We found an executable, now let's launch.
			STARTUPINFO si;
			ZeroMemory(&si, sizeof si);
			si.cb = sizeof si;
			PROCESS_INFORMATION pi;
			ZeroMemory(&pi, sizeof pi);

			// Build a command-line, with the program to start as first argument, quote if necessary
			// convert to short if the app is a 16-bit app.
			auto_ptr<TCHAR> szCmdLine;
			if (Is16BitExe(szExec)) {
				// 16-bit app - convert name to short form, if possible, first.
				TCHAR szShortDocumentName[MAX_PATH];
				if (GetShortPathName(szDocumentName, szShortDocumentName, MAX_PATH)) {
					// Successful conversion, use the short name without quotes.
					szCmdLine = auto_ptr<TCHAR>(FormatSz(_T("\"%1\" %2"), szExec, szShortDocumentName));
				} else {
					// Conversion failed, use what we have, unquoted.
					szCmdLine = auto_ptr<TCHAR>(FormatSz(_T("\"%1\" %2"), szExec, szDocumentName));
				}
			} else if (_tcschr(szDocumentName, _T(' '))) {
				// Spaces in file-name - quote it.
				szCmdLine = auto_ptr<TCHAR>(FormatSz(_T("\"%1\" \"%2\""), szExec, szDocumentName));
			} else {
				// No spaces in file-name - don't quote it.
				szCmdLine = auto_ptr<TCHAR>(FormatSz(_T("\"%1\" %2"), szExec, szDocumentName));
			}

			if (CreateProcess(szExec, szCmdLine.get(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
				// Give the application a second to settle and initialize...
				WaitForInputIdle(pi.hProcess, 1000);
				// Close the handles - we don't need them right now. The reason I don't use this info
				// to determine the child process is because it's not always the process we launch that
				// actually does the work...
				// We might not get a thread-handle, if the program is a 16-bit program.
				if (pi.hThread) {
					CAssert(CloseHandle(pi.hThread)).Sys(MSG_SYSTEM_CALL, _T("CloseHandle(pi.hThread) [MyShellExecute()]")).Throw();
				}
				CAssert(CloseHandle(pi.hProcess)).Sys(MSG_SYSTEM_CALL, _T("CloseHandle(pi.hProcess) [MyShellExecute()]")).Throw();
				return true;
			}
		} else {
			// Translate to standard error messages
			switch (dwRet) {
			case SE_ERR_FNF:
				SetLastError(ERROR_FILE_NOT_FOUND);
				break;
			case SE_ERR_NOASSOC:
				SetLastError(ERROR_NO_ASSOCIATION);
				break;
			case SE_ERR_OOM:
				SetLastError(ERROR_OUTOFMEMORY);
				break;
			default:
				SetLastError(ERROR_INVALID_FUNCTION);
			}
		}
		return false;
	*/
}

bool
CheckIfNotObviouslyDangerous(const wchar_t* szFileName) {
	DWORD dwAllowPrograms = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValAllowPrograms).GetDword(-1);
	if (dwAllowPrograms == -1) {
		dwAllowPrograms = CRegistry(HKEY_LOCAL_MACHINE, gszAxCryptRegKey, szRegValAllowPrograms).GetDword(0);
	}

	// If we've explicitly set that we allow programs, don't warn.
	if (dwAllowPrograms == 1) {
		return true;
	}

	CFileName fileName(szFileName);

	SHFILEINFO sfi;
	ZeroMemory(&sfi, sizeof sfi);
	if (SHGetFileInfo(fileName.Get(), 0, &sfi, sizeof sfi, SHGFI_EXETYPE) != 0) {
		CMessage cMsg;
		cMsg.AppMsg(WRN_DANGEROUS_LAUNCH, CStrPtr(fileName.GetTitle()));
		int response = cMsg.ShowWarning(MB_YESNO);
		if (response != IDYES) {
			return false;
		}
	}
	return true;
}

//
//	Launch an app and wait until it is done with the file
//
//	There is too much ad hoc code here - there is no really
//	proper way to do it it seems, but better would be to hook
//	file open/close.
//
//	The logic is somewhat convoluted since there is no really one good way to figure out
//	if a launched app is done with a file. An app may, or may not, result in a new process
//	that can be waited for. An app may, or may not, keep the file opened with no sharing
//	as long as the app is open. We try to handle all these cases, sometimes resulting in
//	slightly non-intuitive results for the user unfortunately. Basically the rule will be:
//	close the whole app, then Xecrets File will definitely become aware of the fact. In an MDI-type
//	of app it may not be enough to just close the actual document.
//
//	We have two things to look for: A process to wait for and/or Release of the file. The
//	logic is basically:
//
//	Launch the app - possibly via 'Open With...' dialogue.
//
//	if (file-is-locked-by-app) {
//		wait for file, then clean up. Disregard process.
//	} else if (there is an app to wait for) {
//		wait for app to exit.
//		Give a possible older instance a little bit of time, yield up to 1/10th sec...
//		if (file-is-locked-by-app) {
//			wait for file. (Sometimes an app will move control to an older instance...)
//		}
//		clean up.
//	} else {
//		Give message, and let the user press 'Ok' or 'Wait some more'.
//		when 'Ok' - clean up.
//	}
//
// Here's a list of some of the situations we need to handle:
//
// 1 - The standard case. The application is a single document application, locks the file during edit, unlocks it only
// when it is done with it. We can then monitor the file, and when it's unlocked we can re-encrypt.
//
// 2 - The notepad case (simple). The application is a single document application, but does not lock the file during
// edit. We can then wait for the application to exit, provided we can figure out which one it is. This causes the
// side-effect that if you inside the app save the file, and then open a different document, we'll still be waiting.
//
// 3 - The notepad case (double-launch). The application is a single document application, but does not lock the file
// during edit. Then, for example in the notepad case, if the file is too large for it, it won't open the file at all,
// but instead ask the user if she would like to start WordPad instead. If the user says 'yes', notepad exits, and
// WordPad is launched instead. If the user says 'no', notepad just exits. We must now detect that Notepad has launched
// a child, and wait for that.
//
// 4 - The 'open with' case. There's no application associated with the extension, so the 'open with'-dialog is shown.
// We must now detect that (in our case we detect it before trying, and then present the open with dialog ourselves),
// and then figure out which child of the open with-dialog process is actually launched. Then it all starts over again
// essentially...
//
// 5 - The MDI-case, like word. The launch may or may not start a new application, then the document is opened in a
// window inside the application. For Word we can detect that the file is kept locked (unless it's a read-only file...).
// We can also find that a new thread was started, or a new window was created.
//
// 6 - The Open Office-case. OO keeps an internal thread-pool that get's re-used in a complex manner, and is also an
// MDI-application.
//
// The current strategy is thus a very complex interaction of various heuristic ways to make this work.
//
// 1 - Xecrets File checks for the file getting locked, and assumes that if it stays locked for an appreciable amount of time
// after the application has reached Input Idle state, we can trust that when it's released for an appreciable amount of
// time, the application is done with it.
//
// 2 - Xecrets File checks for new processes, and child processes of new processes.
//
// 3 - Xecrets File checks for new threads of processes that have the same executable as that which is associated with the
// files extension.
//
// 4 - Xecrets File checks for new windows.
//
/// \param szApp2Use The application to use instead of the associated one.
void
LaunchApp(LPCTSTR szFileName, const TCHAR* szDir, HWND hForegroundWnd, LPCTSTR szApp2Use) {
	CCriticalSection utLaunchAppCritical(&gLaunchAppCritical);
	utLaunchAppCritical.Enter();
	//BringWindowToTop(hForegroundWnd);

	//
	// The code below is mostly to compensate for deficiencies in Win32 API
	// concerning tracking of process id's etc, especially finding children,
	// and children of children.
	//

	// Child snapshot object
	CChildProc utAppProc;

	// Ensure that no other thread launches an app until we have determined
	// the child process id
	BOOL fLaunchAppOk;
	DWORD dwLaunchErrorCode;

	TCHAR szExec[MAX_PATH];
	DWORD dwRet;

	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [Starting - filename]"), szFileName).LogEvent();
	CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [Starting - GetCurrentProcessId()]"), GetCurrentProcessId()).LogEvent(1);

	if ((dwRet = (DWORD)(LONG_PTR)FindExecutable(szFileName, NULL, szExec)) <= 32) {
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [FindExecutable failed]"), szFileName).LogEvent();

		// Translate to standard error messages
		switch (dwRet) {
		case SE_ERR_FNF:
			SetLastError(ERROR_FILE_NOT_FOUND);
			break;
		case SE_ERR_NOASSOC:
			SetLastError(ERROR_NO_ASSOCIATION);
			break;
		case SE_ERR_OOM:
			SetLastError(ERROR_OUTOFMEMORY);
			break;
		default:
			SetLastError(ERROR_INVALID_FUNCTION);
		}
		// All other errors but no association cause an error. We continue even with no
		// assoc, as it seems the implementation of ShellExec and FindExecutable or not
		// quite equivalent. In any case, we want to give the user the option later if
		// there is no association.
		CAssert(dwRet == SE_ERR_NOASSOC).Sys(MSG_SYSTEM_CALL, _T("FindExecutable() [LaunchApp()]")).Throw();
	}

	// Enter a critical section so as to stop any other thread from launching now.
	{
		//CCriticalSection utLaunchAppCritical(&gLaunchAppCritical);
		//utLaunchAppCritical.Enter();

		// Mark the state of child processes and likely threads before launch.
		utAppProc.Mark(GetCurrentProcessId(), szExec);

		HWND hForeWnd = GetForegroundWindow();

		if (!(fLaunchAppOk = MyShellExecute(szFileName, szDir, szApp2Use))) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [MyShellExecute failed]"), szFileName).LogEvent();
			dwLaunchErrorCode = GetLastError();
		}
		else {
			// Attempt to wait for the foreground window to change, up to 1/2 sec.
			utAppProc.Diff(false, ForegroundWait(hForeWnd, 500));           // Get the change in state of processes and threads
		}
		//utLaunchAppCritical.Leave();
	}

	// If not launch ok - try open with dialog
	if (!fLaunchAppOk) {
		CAssert(dwLaunchErrorCode == ERROR_NO_ASSOCIATION, dwLaunchErrorCode).File(MSG_SHELL_EXECUTE, szFileName).Throw();

		PROCESS_INFORMATION ProcessInfo;
		ZeroMemory(&ProcessInfo, sizeof ProcessInfo);

		STARTUPINFO StartupInfo;
		ZeroMemory(&StartupInfo, sizeof StartupInfo);
		StartupInfo.cb = sizeof StartupInfo;

		CStrPtr szCmdLine = CStrPtr(_T("rundll32.exe shell32.dll,OpenAs_RunDLL ")) + CStrPtr(szFileName);

		CChildProc utOpenWithProc;
		// Ensure that no other thread launches an app until we have determined
		// the child process id
		{
			//CCriticalSection utLaunchAppCritical(&gLaunchAppCritical);
			//utLaunchAppCritical.Enter();
			//utOpenWithProc.TakeSnapshot(GetCurrentProcessId());
			CAssert(CreateProcess(
				NULL,
				szCmdLine,
				NULL,
				NULL,
				FALSE,
				0,
				NULL,
				NULL,
				&StartupInfo,
				&ProcessInfo)).File(MSG_SHELL_EXECUTE, szFileName).Throw();
			//utLaunchAppCritical.Leave();
		}

		CAssert(ProcessInfo.dwProcessId != 0).File(MSG_OPEN_WITH, szFileName).Throw();

		// Here we don't need a critical sections, since the open with
		// process can not launch multiple children. We have no idea of the executable
		// launched either, so we have no chance of tracking threads. Too bad.
		HWND hForeWnd = GetForegroundWindow();
		utAppProc.Mark(ProcessInfo.dwProcessId, _T(""));

		// Wait for the user to pick something to run.
		(void)MessageWaitForSingleObject(ProcessInfo.hProcess);
		// In the best of worlds, the open-with dialog would return an error status if you press cancel...
		DWORD dwExitCode;
		CAssert(GetExitCodeProcess(ProcessInfo.hProcess, &dwExitCode)).Sys(MSG_SYSTEM_CALL, _T("GetExitCodeProcess(ProcessInfo.hThread) [LaunchApp()]")).Throw();

		// Get the new process (if any...)
		utAppProc.Diff(false, ForegroundWait(hForeWnd, 500));

		CAssert(CloseHandle(ProcessInfo.hThread)).Sys(MSG_SYSTEM_CALL, _T("CloseHandle(ProcessInfo.hThread) [LaunchApp()]")).Throw();
		CAssert(CloseHandle(ProcessInfo.hProcess)).Sys(MSG_SYSTEM_CALL, _T("CloseHandle(ProcessInfo.hProcess) [LaunchApp()]")).Throw();
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [OpenWith Succeeded]"), szFileName).LogEvent();
	}

	// If we found child processes, wait for them stabilize
	if (utAppProc.ProcessFound()) {
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [utAppProc.ProcessFound(1)]"), szFileName).LogEvent();
		utAppProc.WaitForInputIdle(szFileName);
	}

	// Now we've done the best we can to assure that we know as much as possible about child
	// processes started, threads started because of the launch, and that eventual child
	// processes have stabilized. Time for the waiting strategy.
	//
	// We can determine that the application is done with the file in three ways:
	// 1 - It has a lock on the file, which it releases.
	// 2 - The launched child process(es) exits.
	// 3 - The launched thread(s) exits.
	//
	// If we know there's a child-process, waiting for it to finish is pretty sure, but
	// it may take a long time - consider a typical MDI-application such as Word.
	// The thread detection is not exactly rocket science, so that becomes our last option.
	//
	// Thus, we start by hoping the application actually locks the file, and then assume
	// that if the file is relased, the app is really done with it - unless there are files
	// left in the directory, in which case we assume this is temp-files or similar, and
	// wait for the application itself to exit.
	//
	// Since there are problems with false-positive-exits, we check for all conditions
	// to apply before exiting. A specific situation where this is a problem is if in
	// word for example, you do a 'save-as' to a different file. The original file
	// is then released, and Xecrets File will attempt to move the new file if it was
	// accidently saved in the Xecrets File directory to the original source directory. In
	// this case it can't do that, as it's now open by word again.
	//
	// Finally, if we don't know the child process, we wait for known started threads (if any)
	// to exit.
	//
	// If we've failed in gathering any of the above, we warn the user to tell us manually when
	// he's done.

	//	Give it up to 1/2 second to lock the file - it turns out that not even waiting for InputIdle
	//	is enough for some apps, notably Acrobat Reader for example, and then wait for it to become
	//	free again.
	//  Start by always waiting. The user must keep the file open for at least 3 seconds if we are to
	//  use this optimized stragegy - otherwise we fall back on process and thread-waiting.
	utLaunchAppCritical.Leave();
	bool fUnlocked = WaitForLockThenUnlock(szFileName, 500, 100, 3000) != 0;
	// At this point, if fUnlocked == TRUE, we know that an application has opened the file,
	// locked it, and released it. We now check to see if the directory only contains
	// this file - if so, we will assume that we're really done with it even if the actual
	// process is still running. This handles the case of Office programs staying active,
	// even after closing the document window as such. This should work regardless of
	// if we found any process or thread...
	if (fUnlocked) {
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [fUnlocked]"), szFileName).LogEvent();
		// We have detected a definite lock and then unlock on the file, let's see if there are
		// any other files in the directory. This is very dependent on the idea that we're working
		// in our own temporary directory at this point, where we know what kind of files are supposed
		// to be there - but the worst effect is that we need to stay and wait for an application
		// even if this assumption turns out to be false. Still, this code overall is becoming
		// messy...
		if (OnlyThisFileInDir(szFileName)) {
			// There's only this file! Then we say it's safe to say that as far as we are concerned,
			// this is done, and we do not need to wait for processes or threads.
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("Lock-unlock and no extra files in OpenLaunch"), szFileName).LogEvent();
			return;
		}
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("Lock-unlock with extra files in OpenLaunch"), szFileName).LogEvent();
	}
	//
	// After all this, we still have not been able to detect a lock on the file! Let's fall back on
	// the process if we have one. Notepad is such an example...
	// We may also have found other files in the directory we're working in.
	if (utAppProc.ProcessFound()) {
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [utAppProc.ProcessFound(2)]"), szFileName).LogEvent();
		// If we at least think we started a process, let's see if we can wait for it...
		// This might fail, if the process is terminated before we get here.
		//
		//  What also might happen is that the started process starts another process and exits...
		//  This happens for example with too-large notepad files, suggesting wordpad instead....
		//  We're not carrying this to the extreme - so we're just handling one such level.
		//
		if (fUnlocked) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [utAppProc.WaitForProcess()]"), szFileName).LogEvent();
			utAppProc.WaitForProcess();
		}
		else {
			// Look for new-come children only if the original app did not lock the file.
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [utAppProc.WaitForProcessAndNewChildren()]"), szFileName).LogEvent();
			utAppProc.WaitForProcessAndNewChildren();
		}

		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("End Waiting for process in OpenLaunch"), szFileName).LogEvent();
	}
	else if (fLaunchAppOk && utAppProc.ThreadFound()) {
		// We found one or more candidate threads of a successful initial launch, lets wait for them all to go away
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("Start Waiting for thread in OpenLaunch"), szFileName).LogEvent();
		utAppProc.WaitForThread();
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("End Waiting for thread in OpenLaunch"), szFileName).LogEvent();
	}
	else if (!fUnlocked) {
		CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [!fUnlocked]"), szFileName).LogEvent();
		// if there was no process or thread to wait for, and the file was not immediately locked
		// This is a problem, but let's wait up to 10 seconds to let the app find and lock the file.
		if (!WaitForLockThenUnlock(szFileName, 10000, 100, 3000)) {
			CMessage().Wrap(0).AppMsg(INF_DEBUG2, _T("LaunchApp: [!WaitForLockThenUnlock]"), szFileName).LogEvent();
			// If after 5 seconds the app still did not lock it
			// Display dialog and wait etc.
			CMessage().AppMsg(WRN_CANT_TELL_DONE, CFileName(szFileName).GetTitle()).ShowDialog(MB_ICONWARNING | MB_OK);
		}
	}
}

/// \brief Local helper to save extra-saved files
/// Here we assume that we don't have to worry about
/// progress windows.
static DWORD
LocalCmdSaveExtraFilesNoProgress(CCmdParam* pCmdParam) {
	// Filter out names that we classify as temporaries
	if (IsTempFile(pCmdParam->szParam1.c_str())) {
		return 0;
	}

	SHFILEOPSTRUCT shfo;
	ZeroMemory(&shfo, sizeof shfo);

	// Build a double-nul-terminated from
	size_t ccFrom = _tcslen(pCmdParam->szParam1.c_str()) + 2;
	auto_ptr<TCHAR> szzFrom(new TCHAR[ccFrom]);
	ASSPTR(szzFrom.get());

	_tcscpy_s(szzFrom.get(), ccFrom, pCmdParam->szParam1.c_str());
	// Append a second nul
	szzFrom.get()[_tcslen(szzFrom.get()) + 1] = _T('\0');

	// Build a double-nul-terminated to
	TCHAR* szFileTitle = PathFindFileName(pCmdParam->szParam1.c_str());
	size_t ccTo = _tcslen(pCmdParam->szParam2.c_str()) + 1 + _tcslen(szFileTitle) + 2;
	auto_ptr<TCHAR> szzTo(new TCHAR[ccTo]);
	ASSPTR(szzTo.get());

	_tcscpy_s(szzTo.get(), ccTo, pCmdParam->szParam2.c_str());

	// Append the default file-name too.
	PathAppend(szzTo.get(), szFileTitle);
	szFileTitle = PathFindFileName(szzTo.get());
	// Append a second nul
	szzTo.get()[_tcslen(szzTo.get()) + 1] = _T('\0');

	shfo.hwnd = GetForegroundWindow();
	shfo.wFunc = FO_MOVE;
	shfo.pFrom = szzFrom.get();
	shfo.pTo = szzTo.get();
	shfo.fFlags = FOF_NORECURSION;

	// Do the actual move, if it fails, ask for a different name until the user presses cancel.
	bool fRetry;
	do {
		// Lock reference to the current directory while we're operating in the SHFileOperation.
		CCriticalSection critCurDir(&gCurrentDirectoryCritical, TRUE);

		fRetry = false;
		if (SHFileOperation(&shfo) != 0) {
			// Wait up to 200ms for a new foreground window to appear.
			(void)ForegroundWait(shfo.hwnd, 200);

			// If the file operation fails, we try to ask the user for some other place to
			// save the file.
			size_t ccFileName = MAX_PATH;
			auto_ptr<TCHAR> szFileName(new TCHAR[ccFileName]);
			ASSPTR(szFileName.get());

			_tcsncpy_s(szFileName.get(), ccFileName, szFileTitle, MAX_PATH);
			szFileName.get()[ccFileName - 1] = _T('\0');

			// Now get the directory-part
			auto_ptr<TCHAR> szDir(_tcsdup(szzTo.get()));
			ASSPTR(szDir.get());

			PathRemoveFileSpec(szDir.get());

			// Build the filter string, i.e. for example "*.txt\0*.txt\0\0"
			// They don't make it easy by using nul chars...
			TCHAR szFilter[MAX_PATH + MAX_PATH + 3];
			TCHAR* szPathExt = PathFindExtension(szFileName.get());
			if (szPathExt[0]) {
				_stprintf_s(szFilter, sizeof szFilter / sizeof szFilter[0], _T("*%s"), szPathExt);
				size_t offFilterPart2 = _tcslen(szFilter) + 1;
				size_t ccFilterPart2 = (sizeof szFilter / sizeof szFilter[0]) - offFilterPart2;
				_TCHAR* szFilterPart2 = &szFilter[offFilterPart2];
				_stprintf_s(szFilterPart2, ccFilterPart2, _T("*%s"), szPathExt);
				szFilterPart2[_tcslen(szFilterPart2) + 1] = _T('\0');
			}
			else {
				// Copy default filter, if no extension.
				CopyMemory(szFilter, _T("*.*\0*.*\0"), sizeof _T("*.*\0*.*\0"));
			}

			OPENFILENAME ofn;
			ZeroMemory(&ofn, sizeof ofn);
			ofn.lStructSize = sizeof ofn;
			ofn.hwndOwner = GetForegroundWindow();
			ofn.lpstrFilter = szFilter;
			ofn.nFilterIndex = 1;
			ofn.lpstrDefExt = szPathExt[0] ? szPathExt + 1 : NULL;
			ofn.lpstrInitialDir = szDir.get();
			ofn.lpstrFile = szFileName.get();
			ofn.nMaxFile = MAX_PATH;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_NOREADONLYRETURN | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;

			if (GetSaveFileName(&ofn) == TRUE) {
				size_t ccTo = _tcslen(ofn.lpstrFile) + 2;
				szzTo = auto_ptr<TCHAR>(new TCHAR[ccTo]);
				ASSPTR(szzTo.get());

				_tcscpy_s(szzTo.get(), ccTo, ofn.lpstrFile);
				szFileTitle = PathFindFileName(szzTo.get());
				// Append a second nul
				szzTo.get()[_tcslen(szzTo.get()) + 1] = _T('\0');
				// Update the file operation structure with the new name.
				shfo.pTo = szzTo.get();
				fRetry = true;
			}
		}
	} while (fRetry);

	return 0;
}
//
//  Local helper to save extra-saved files. It accepts a full path name as
//  param1, and a directory to use as default as param2.
//
//  We filter out known temporary file names etc.
//
static DWORD
LocalCmdSaveExtraFiles(CCmdParam* pCmdParam) {
	// Ensure that we shut of progress window
	if (pCmdParam->hProgressWnd != NULL) {
		SendMessage(GetParent(pCmdParam->hProgressWnd), WM_APP, 0, 0);
	}
	DWORD dwRet = LocalCmdSaveExtraFilesNoProgress(pCmdParam);
	// RE-enable progress window
	if (pCmdParam->hProgressWnd != NULL) {
		SendMessage(GetParent(pCmdParam->hProgressWnd), WM_APP + 2, 0, 0);
	}
	return dwRet;
}
/// \brief Wrap a plain to a cipher, catch exceptions, display message and return status instead
/// \param utWrap A wrapper class instantiation to use
/// \param fPlain An open plain text file to be wrapped
/// \param fCipher An open cipher file to wrap to. Is closed on success
/// \param fnCipher The file name of the destination file.
/// \return true if wrap operation succeeded, otherwise false after message
static bool
WrapFileErrMsgStatus(CWrapper& utWrap, CFileIO& fPlain, CFileIO& fCipher, CFileName& fnCipher, DWORD nWipePasses, BOOL fSlowSafe = TRUE, BOOL fEnableProgress = TRUE) {
	try {
		CCriticalSection utLaunchAppCritical(&gLaunchAppCritical);
		utLaunchAppCritical.Enter();

		// Start by truncating the file. This is a cipher file, so there's
		// no real problem if data don't get wiped at the end.
		fCipher.SetFilePointer(0);
		fCipher.SetEndOfFile();

		// Re-wrap it
		utWrap.Wrap(fPlain, fCipher, nWipePasses, fSlowSafe, fEnableProgress);
		fCipher.Close(TRUE);					// Close and keep

		// Set encrypted file-times to plain-file times, if the default from 1.5.2.2 has changed.
		if (CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValKeepTimeStamp).GetDword() != 0) {
			// Re-open after close and flush to set proper file-times.
			fCipher.Open(fnCipher.Get(), FALSE, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE);
			fCipher.SetFileTimes(fPlain.GetFileTimes());    // Set the encrypted file-times as the plain
			fCipher.Close();
		}
		utLaunchAppCritical.Leave();
	}
	catch (TAssert utErr) {
		// Display error message if not in server mode
		if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
			// If it was a cancel we caught, we just show that, otherwise an error message.
			if (utErr.LastError() == WRN_CANCEL) {
				utErr.App(WRN_CANCEL).Show();
			}
			else {
				utErr.File(MSG_WRAP_ERROR, fnCipher.GetTitle()).Show();
			}
			return false;
		}
		else {
			throw;
		}
	}
	return true;
}
//
//  Look for extra-saved files, left-overs etc in the temporary directory.
//  The typical case we're trying to handle is when the user (or the app) has
//  done save of other files than the one we've opened to the temporary directory.
//
//  We scan the directory and sub-directories for files, and call a helper
//  to ask the user where to save them.
//
DWORD
SaveExtraFiles(const TCHAR* szDirToScan, const TCHAR* szDirToSaveTo, HWND hWnd, HWND hProgressWnd) {
	CCmdParam cmdParam;
	cmdParam.hForegroundWnd = hWnd;
	cmdParam.hProgressWnd = hProgressWnd;
	cmdParam.szParam2 = szDirToSaveTo;
	return FileExpand(LocalCmdSaveExtraFiles, &cmdParam, szDirToScan, _T("*"));
}
//
//	Deccrypt the named file, launch the application, and wait for exit and free file.
//
// szParam2 may, if non-blank, contain the name of an application to use for
// launching, instead of the default associated.
//
// "Primary Execute Request Thread"
//
//	Return status code of the thread.
//
DWORD
CmdDecryptOpenLaunch(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	bool fIsExpired = IsExpired();

	// If necessary, set current directory
	CFileName fnCipher;
	fnCipher.Set(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str());

	if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValServerMode).GetDword(FALSE)) {
		CCriticalSection utLaunchAppCritical(&gLaunchAppCritical);
		utLaunchAppCritical.Enter();

		HEAP_CHECK_BEGIN(_T("CmdDecryptOpenLaunch()"), 0)
			// Do not attempt to remove the directory until we exit the function, otherwise there may
			// be strange effects with left-over files if the destructors are called in the wrong order.
			CTempDir utTempDir(pCmdParam->nWipePasses);
		utTempDir.New();
		try {
			// If not overridden, verify that the file has the correct extension
			if (!CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValAllowAnyExtension).GetDword(FALSE)) {
				CAssert(_tcsicmp(fnCipher.GetExt(), gszAxCryptFileExt) == 0).App(MSG_INVALID_EXT).Throw();
			}

			// These will auto-close upon destruction.
			CFileIO utFileCipher, utFilePlain;
			CHeaders utHeaders;

			// Thanks D. Nay for pointing out the need for checking read-only cases.
			CReadOnlyMgr utCipherROM(fnCipher.Get());
			bool bPlainIsReadOnly = utCipherROM.IsReadOnly() || fIsExpired;
			bool bPlainIsHidden = utCipherROM.IsHidden();

			try {
				utFileCipher.Open(fnCipher.Get(), TRUE,
					GENERIC_READ | (utCipherROM.IsReadOnly() ? 0 : GENERIC_WRITE),
					FILE_SHARE_READ);
			}
			catch (TAssert utErr) {
				// If we failed to open, check if it's a sharing violation, and we're not read-only
				if (!utCipherROM.IsReadOnly() && (utErr.LastError() == ERROR_SHARING_VIOLATION)) {
					// But if it is, lets try again but this time forcing read-only. This is
					// is a good place to notify the user about this condition. Asking at this point
					// minmizes the risk for unknown race-conditions, and also makes things a bit clearer
					// for the user. Some applications such as word will recognize that the working copy
					// is read-only, and show this in the title-bar, but others - notably notepad, will
					// not and this causes confusion for the user.
					if (CMessage().Wrap(0).AppMsg(WRN_SHARING_VIOLATION, CMessage().SysMsg(utErr.LastError(), fnCipher.GetTitle()).GetMsg(), fnCipher.GetTitle()).ShowDialog(MB_YESNO | MB_ICONWARNING) == IDYES) {
						bPlainIsReadOnly = true;
						utFileCipher.Open(fnCipher.Get(), TRUE, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE);
					}
					else {
						return WRN_CANCEL;
					}
				}
				else {
					utErr.Throw();      // Send it upwards.
				}
			}

			utLaunchAppCritical.Leave();
			utHeaders.Load(utFileCipher);

			CPtrTo<TKey> pKeyEncKey;
			if (TryCacheAndPromptOpen(&utHeaders, &pKeyEncKey, pCmdParam->dwBatch, fnCipher.GetTitle(), pCmdParam->hProgressWnd)) {
				// Get the real original name from the headers and combine it with a unique
				// temp directory.

				CFileName fnPlain;
				fnPlain.SetDir(utTempDir.Get()).SetTitle(utHeaders.GetFileName());

				// Allow some 'leak' here due to file-name caching by CFileIO
				HEAP_CHECK_BEGIN(_T("CmdDecryptOpenLaunch(a.a)"), TRUE)
					utFilePlain.Create(fnPlain.Get(), TRUE, GENERIC_READ | GENERIC_WRITE);	// create always w/delete-on-close
				HEAP_CHECK_END

					CWrapper utWrap(&utHeaders, pCmdParam->hProgressWnd);

				HEAP_CHECK_BEGIN(_T("CmdDecryptOpenLaunch(a.b)"), 0)
					utWrap.Unwrap(utFileCipher, utFilePlain, pCmdParam->nWipePasses);
				HEAP_CHECK_END

					// Restore the old file times. Close, and re-open
					utFilePlain.Close(TRUE);				// Keep the plain-file.
				utFilePlain.Open(fnPlain.Get(), FALSE, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE);
				utFilePlain.SetFileTimes(utHeaders.GetFileTimes());
				utFilePlain.Close();

				CReadOnlyMgr utPlainROM(fnPlain.Get());

				// Set the copy read-only, if the encrypted file is too, or if we could not open it for read-write
				if (bPlainIsReadOnly) {
					utPlainROM.SetReadOnly();
				}

				// Launch appropriate app
				HEAP_CHECK_BEGIN(_T("CmdDecryptOpenLaunch(a.c)"), 0)
					if (pCmdParam->hProgressWnd != NULL) {
						// Hide it.
						SendMessage(GetParent(pCmdParam->hProgressWnd), WM_APP, 0, 0);
					}

				if (CheckIfNotObviouslyDangerous(fnPlain.Get())) {
					LaunchApp(fnPlain.Get(), fnCipher.GetDir(), GetForegroundWindow()/*pCmdParam->hForegroundWnd*/, pCmdParam->szParam2.c_str());
				}

				HEAP_CHECK_END

					// If the copy was made read-only, restore it to read-write for wipe.
					if (bPlainIsReadOnly) {
						utPlainROM.SetReadWrite();
					}
				// Rewrap if modified
				utFilePlain.Open(fnPlain.Get(), TRUE, GENERIC_READ | GENERIC_WRITE);
				if (!bPlainIsReadOnly && (utHeaders.CompareFileTime(&utFilePlain.GetFileTimes()->LastWriteTime) < 0)) {
					utHeaders.SetFileTimes(utFilePlain.GetFileTimes());
					utHeaders.WrapKeyData(pKeyEncKey);

					// Rewrap, using slow-safe, bug disable progress windows. We do not want the user to be able to abort
					// this, since there's really no good point in doing so. Since we're writing directly to the destination
					// (which may be debatable), an abort is really just bad. There's actually no really good way to abort it
					// since the source is modified and needs to be written. So we don't give the option.
					while (!WrapFileErrMsgStatus(utWrap, utFilePlain, utFileCipher, fnCipher, pCmdParam->nWipePasses, TRUE, FALSE)) {
						// Wrapping failed - present user with a dialogue asking for a new place
						// to save.

						// First do a fault-tolerant forced close as well as we can.
						utFileCipher.ForceClose();

						// Then try to create and open a new file to save to. This can cause an exception
						// if the user presses cancel, in which case we exit.
						CreateSaveFile(&utFileCipher, fnCipher, CREATE_NEW, GetForegroundWindow(), true);
					}
					if (bPlainIsHidden) {
						utCipherROM.SetHidden();
					}
					// CmdDecryptOpenLaunch: We've done a re-wrap - that counts.
					IncrementTrialCtr();
				}
				else {
					utFileCipher.Close();					// Close and keep
				}

				// Hide progress window, if any. We do this before wiping, as it's done
				// in the background pretty much anyway.
				if (pCmdParam->hProgressWnd) {
					SendMessage(GetParent(pCmdParam->hProgressWnd), WM_APP, 0, 0);
				}

				utFilePlain.WipeTemp(pCmdParam->hProgressWnd, pCmdParam->nWipePasses); 		// Implies delete-on-close
				utFilePlain.Close();					// Close and delete.

				// Scan temporary directory for left-over or extra-saved files.
				SaveExtraFiles(fnPlain.GetDir(), fnCipher.GetDir(), GetForegroundWindow(), pCmdParam->hProgressWnd);
			}
		}
		catch (TAssert utErr) {
			// Hide progress window, if any.
			if (pCmdParam->hProgressWnd) {
				SendMessage(GetParent(pCmdParam->hProgressWnd), WM_APP, 0, 0);
			}
			utErr.File(MSG_OPEN_LAUNCH, fnCipher.GetTitle()).Show();
		}
		//BringWindowToTop(pCmdParam->hForegroundWnd);
		return 0;
		HEAP_CHECK_END
	}
	else {
		CMessage().Wrap(0).AppMsg(ERR_LOG_OPEN_IN_SERVER_MODE, pCmdParam->szParam1.c_str()).LogEvent(0);
		return WRN_CANCEL;
	}
}
//
//	Securely wipe the file and then delete it. No confirmation question.
//
DWORD
CmdWipeSilent(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	// If necessary, set current directory
	CFileName fnFile2Wipe;
	fnFile2Wipe.Set(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str());

	HEAP_CHECK_BEGIN(_T("CmdWipeSilent()"), 0)

		try {
		// If we should show a possible warning,
		// Check the attributes for those we cannot wipe properly.
		CRegistry utRegWarn(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValNoUnsafeWipeWarn);
		BOOL fNotAgain = utRegWarn.GetDword(FALSE);
		if (!fNotAgain) {
			DWORD dwAttrib = GetFileAttributes(fnFile2Wipe.Get());
			CAssert(dwAttrib != 0xFFFFFFFF).Sys(MSG_SYSTEM_CALL, fnFile2Wipe.GetTitle()).Throw();
			if (dwAttrib & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_SPARSE_FILE)) {
				bool fOk = WarningDlg(fnFile2Wipe.GetTitle(), WRN_INSECURE_WIPE, INF_DONTREPEAT, fNotAgain);
				if (fNotAgain) {
					utRegWarn.SetDword(fNotAgain);
				}
				if (!fOk) {
					return WRN_CANCEL;
				}
			}
			// Silently ignore requests to wipe folders/directories
			if (dwAttrib & FILE_ATTRIBUTE_DIRECTORY) {
				return 0;
			}
		}

		CFileIO utFile2Wipe;
		utFile2Wipe.Open(fnFile2Wipe.Get(), TRUE, GENERIC_READ | GENERIC_WRITE);
		utFile2Wipe.WipeData(pCmdParam->hProgressWnd, pCmdParam->nWipePasses);		// Also sets delete on close
		utFile2Wipe.Close();

		SHChangeNotify(SHCNE_DELETE, SHCNF_PATH, pCmdParam->szParam1.c_str(), NULL);
	}
	catch (TAssert utErr) {
		// Hide progress window, if any.
		if (pCmdParam->hProgressWnd) {
			SendMessage(GetParent(pCmdParam->hProgressWnd), WM_APP, 0, 0);
		}
		return (utErr.File(MSG_WIPE_ERROR, fnFile2Wipe.GetTitle()).Message().ShowError(pCmdParam->dwBatch ? MB_OKCANCEL : MB_OK) == IDCANCEL) ? WRN_CANCEL : 0;
	}
	HEAP_CHECK_END
		return 0;
}
/// \brief Securely wipe the file and the delete it. First ask 'are you sure...'.
/// If there is a batch-id, a yes results in a return of INF_YESALL so we can stop
/// asking.
/// If there is a batch-id, a no results in a return of WRN_CANCEL since that is
/// more appropriate
DWORD
CmdWipe(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	if (IsExpired()) {
		return WRN_CANCEL;
	}

	// If necessary, set current directory
	CFileName fnFile2Wipe;
	fnFile2Wipe.Set(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str());

	DWORD dwReturn = 0;

	HEAP_CHECK_BEGIN(_T("CmdWipe()"), 0)

		BringWindowToTop(GetForegroundWindow());

	axpl::ttstring s = MainDlgTitleBar();
	switch (MessageBox(GetForegroundWindow(),
		CMessage().AppMsg(pCmdParam->dwBatch ? WRN_REALLY_WIPE_ALL : WRN_REALLY_WIPE,
			fnFile2Wipe.GetTitle()).GetMsg(),
		s.c_str(),
		MB_YESNO | MB_ICONERROR | MB_DEFBUTTON2 | MB_TOPMOST)) {
	case IDYES:
		// If we're in batched mode, and the user pressed 'yes', indicate this to caller
		// as INF_YESALL.
		if (!(dwReturn = CmdWipeSilent(pCmdParam))) {
			// CmdWipe: A wipe counts.
			IncrementTrialCtr();
			return pCmdParam->dwBatch ? INF_YESALL : 0;
		}
		else {
			return dwReturn;
		}
		break;

	case IDCANCEL:
		// This will cause batched operations to stop.
		return WRN_CANCEL;
		break;

	case IDNO:
		return pCmdParam->dwBatch ? WRN_CANCEL : 0;
		break;

	default:
		break;
	}
	HEAP_CHECK_END
		return 0;
}
//
//  Clear keys in memory, belonging to a specific batch if given,
//  otherwise all.
//
DWORD
CmdClearKeys(CCmdParam* pCmdParam) {
	pgKeyList->ClearKeys(pCmdParam->dwBatch);
	return 0;
}
//
//  Add keys to our memory. Handle especially if it is the default
//  encryption key.
//
//  Careful... Here we should be working in ANSI to maintain key
//  compatibility...
//
DWORD CmdAddKey(CCmdParam* pCmdParam) {
	// Just ignore empty key requests.
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	//
	//  Filter the key using the same criteria as the the Password entry
	//  dialog. Remember about Unicode and Ansi...
	//
	std::string s = axpl::t2s(std::wstring(pCmdParam->szParam1));
	const char* pNxtInChar = s.c_str();

	// Ensure that szFilterKey is deallocated on exit of this function.
	CPtrTo<char> szFilterKey;
	szFilterKey = new char[strlen(pNxtInChar) + 1];
	ASSPTR(szFilterKey);

	char* pNxtOutChar = szFilterKey;

	while (*pNxtInChar) {
		if (strchr((const char*)szPassphraseChars, *pNxtInChar) != NULL) {
			*pNxtOutChar++ = *pNxtInChar;
		}
		pNxtInChar++;
	}
	*pNxtOutChar = '\0';

	// We are responsible for ensuring the deletion of the returned key hash pointer
	CPtrTo<TKey> utKey = CSha1().GetKeyHash((BYTE*)(char*)szFilterKey, strlen(szFilterKey));

	if (pCmdParam->fIsEncKey) {
		// AddEncKey checks with find key first...
		(void)pgKeyList->AddEncKey(utKey, pCmdParam->dwBatch);
	}
	else {
		// Check if we already know the key...
		if (!pgKeyList->FindKey(utKey, pCmdParam->dwBatch, FALSE)) {
			// ...if not - add it to the list of known keys.
			pgKeyList->AddKey(utKey, FALSE, pCmdParam->dwBatch);
		}
	}
	return 0;
}

#define ATL_BASE64_FLAG_NONE	0
#define ATL_BASE64_FLAG_NOPAD	1
#define ATL_BASE64_FLAG_NOCRLF  2

inline size_t Base64EncodeGetRequiredLength(size_t nSrcLen, DWORD dwFlags = ATL_BASE64_FLAG_NONE) throw()
{
	size_t nRet = nSrcLen * 4 / 3;

	if ((dwFlags & ATL_BASE64_FLAG_NOPAD) == 0)
		nRet += nSrcLen % 3;

	size_t nCRLFs = nRet / 76 + 1;
	int nOnLastLine = (int)(nRet % 76);

	if (nOnLastLine)
	{
		if (nOnLastLine % 4)
			nRet += 4 - (nOnLastLine % 4);
	}

	nCRLFs *= 2;

	if ((dwFlags & ATL_BASE64_FLAG_NOCRLF) == 0)
		nRet += nCRLFs;

	return nRet;
}

#define ATLASSERT(f) CAssert(f, ERROR_INVALID_FUNCTION).Sys().Throw()

/// \brief Encode Base64 data.
inline BOOL Base64Encode(
	const BYTE* pbSrcData,
	size_t nSrcLen,
	LPSTR szDest,
	size_t* pnDestLen,
	DWORD dwFlags = ATL_BASE64_FLAG_NONE) throw()
{
	static const char s_chBase64EncodingTable[64] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
		'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',	'h',
		'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
		'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

	if (!pbSrcData || !szDest || !pnDestLen)
	{
		return FALSE;
	}

	ATLASSERT(*pnDestLen >= Base64EncodeGetRequiredLength(nSrcLen, dwFlags));

	size_t nWritten(0);
	size_t nLen1((nSrcLen / 3) * 4);
	size_t nLen2(nLen1 / 76);
	size_t nLen3(19);

	for (size_t i = 0; i <= nLen2; i++)
	{
		if (i == nLen2)
			nLen3 = (nLen1 % 76) / 4;

		for (size_t j = 0; j < nLen3; j++)
		{
			DWORD dwCurr(0);
			for (int n = 0; n < 3; n++)
			{
				dwCurr |= *pbSrcData++;
				dwCurr <<= 8;
			}
			for (int k = 0; k < 4; k++)
			{
				BYTE b = (BYTE)(dwCurr >> 26);
				*szDest++ = s_chBase64EncodingTable[b];
				dwCurr <<= 6;
			}
		}
		nWritten += nLen3 * 4;

		if ((dwFlags & ATL_BASE64_FLAG_NOCRLF) == 0)
		{
			*szDest++ = '\r';
			*szDest++ = '\n';
			nWritten += 2;
		}
	}

	if (nWritten && (dwFlags & ATL_BASE64_FLAG_NOCRLF) == 0)
	{
		szDest -= 2;
		nWritten -= 2;
	}

	nLen2 = nSrcLen % 3 ? nSrcLen % 3 + 1 : 0;
	if (nLen2)
	{
		DWORD dwCurr(0);
		for (size_t n = 0; n < 3; n++)
		{
			if (n < (nSrcLen % 3))
				dwCurr |= *pbSrcData++;
			dwCurr <<= 8;
		}
		for (size_t k = 0; k < nLen2; k++)
		{
			BYTE b = (BYTE)(dwCurr >> 26);
			*szDest++ = s_chBase64EncodingTable[b];
			dwCurr <<= 6;
		}
		nWritten += nLen2;
		if ((dwFlags & ATL_BASE64_FLAG_NOPAD) == 0)
		{
			nLen3 = nLen2 ? 4 - nLen2 : 0;
			for (size_t j = 0; j < nLen3; j++)
			{
				*szDest++ = '=';
			}
			nWritten += nLen3;
		}
	}

	*pnDestLen = nWritten;
	return TRUE;
}

/// \brief Generate and save a key-file
/// \param pCmdParam ->szParam1 contains a file name, or not. If not, ask with save-as.
DWORD
CmdMakeKeyFile(CCmdParam* pCmdParam) {
	DWORD dwReturn = 0;
	CFileName keyFileName;

	try {
		CFileIO keyFile;
		bool fAlwaysPromptForSaveAs = true;

		keyFileName.SetCurDir(pCmdParam->szCurDir.c_str());
		if (!pCmdParam->szParam1.empty()) {
			keyFileName.Set(pCmdParam->szParam1.c_str());

			// If we've just got a directory (that exists) add on default file name,
			// and keep the 'always ask first flag' set.
			DWORD dwAttrib = GetFileAttributes(keyFileName.Get());
			if ((dwAttrib != INVALID_FILE_ATTRIBUTES) &&
				(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
				keyFileName.AddName(CMessage().AppMsg(INF_KEYFILE_NAME).GetMsg());
			}
			else {
				fAlwaysPromptForSaveAs = false;
			}
		}
		else {
			keyFileName.Set(CMessage().AppMsg(INF_KEYFILE_NAME).GetMsg());
		}

		// Give a warning about what we're about to do
		CRegistry utRegWarn(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValKeyFileInfo);
		BOOL fNotAgain = utRegWarn.GetDword(FALSE);
		if (!fNotAgain) {
			bool fOk = WarningDlg(keyFileName.GetTitle(), INF_MAKE_KEYFILE, INF_DONTREPEAT, fNotAgain);
			if (fNotAgain) {
				utRegWarn.SetDword(fNotAgain);
			}
			if (!fOk) {
				return WRN_CANCEL;
			}
		}

		CreateSaveFile(&keyFile, keyFileName, CREATE_NEW, GetForegroundWindow(), fAlwaysPromptForSaveAs);

		if (GetDriveType(CFileName().SetDrive(keyFileName.GetDir()).GetRootDir()) != DRIVE_REMOVABLE) {
			// Give a warning about what we're about to do
			CRegistry utRegWarn(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValKeyFileNotRemovable);
			BOOL fNotAgain = utRegWarn.GetDword(FALSE);
			if (!fNotAgain) {
				bool fOk = WarningDlg(keyFileName.GetTitle(), WRN_NOT_REMOVABLE, INF_DONTREPEAT, fNotAgain);
				if (fNotAgain) {
					utRegWarn.SetDword(fNotAgain);
				}
				if (!fOk) {
					return WRN_CANCEL;
				}
			}
		}

		// Generate a nice, random 256-bit key for us. This and the following code
		// contains some hard-coded constants depending on the fact that we know
		// how large and long the data is etc.
		unsigned char ucKey[256 / 8];
		pgPRNG->Seed(NULL, 0).RandomFill(ucKey, sizeof ucKey);

		// Just for readabilitys sake, if the user ever has to re-enter it manually,
		// if someone ever actually prints it for backup... Let's do it a little bit
		// easier for the user by separating into groups.
		char cBase64Key[gcbAxCryptKeyFile + 1];

		// Base64-encode the key. Note that Base64Encode does not support
		// wide/tchar, nor does it append a nul-byte!
		size_t i, j;
		for (i = 0, j = 0; i < sizeof ucKey; i += 3, j += 5) {
			if (j) {
				cBase64Key[j - 1] = ' ';
			}
			size_t iLen = 4;
			if (!Base64Encode((BYTE*)&ucKey[i], i + 3 >= sizeof ucKey ? sizeof ucKey - i : 3, &cBase64Key[j], &iLen, ATL_BASE64_FLAG_NOCRLF)) {
				CAssert(FALSE, ERROR_INVALID_FUNCTION).Sys().Throw();
			}
		}
		cBase64Key[--j] = '\0';
		keyFile.WriteData(cBase64Key, &j);
		keyFile.Close(TRUE);

		// Set the result read-only
		CAssert(SetFileAttributes(keyFileName.Get(), GetFileAttributes(keyFileName.Get()) | FILE_ATTRIBUTE_READONLY)).Sys(MSG_SYSTEM_CALL, keyFileName.GetTitle()).Throw();
	}
	catch (TAssert utErr) {
		// No error message on simple cancel request.
		if (utErr.LastError() == WRN_CANCEL) {
			return utErr.LastError();
		}
		dwReturn = HandleCmdException(utErr, pCmdParam, MSG_WRAP_ERROR, keyFileName.GetName());
	}
	return dwReturn;
}
//
//  Ask for keys using the regular prompts, thus ensuring a safe way
//  to enter keys into the cache.
//
DWORD
CmdPromptKey(CCmdParam* pCmdParam) {
	CKeyPrompt utKeyPrompt;
	DWORD dwReturn = 0;

	if (pCmdParam->fIsEncKey) {
		// We know that hProgressWnd is part of a dialogue, and thus the parent of that
		// is what we want to have has parent for the pass phrase dialogue. This is not
		// neat, it's ugly, but the whole window handling needs massive clean-up anyway.
		(void)utKeyPrompt.New(GetParent(GetParent(pCmdParam->hProgressWnd)));
		// If the user entered a key, and did not cancel
		if (utKeyPrompt.Get() != NULL) {
			// Test if we really should save the key here.
			BOOL fSaveEncKey = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveEncKey).GetDword();
			if (fSaveEncKey || pCmdParam->dwBatch != 0) {
				// This is may be a permanent allocation here.
				HEAP_CHECK_BEGIN(_T("CmdPromptKey(a)"), TRUE);
				pgKeyList->AddEncKey(utKeyPrompt.Get(), fSaveEncKey ? 0 : pCmdParam->dwBatch)->Key();
				HEAP_CHECK_END
			}
			BOOL fSaveDecKey = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveDecKey).GetDword(FALSE);
			if (fSaveDecKey || pCmdParam->dwBatch != 0) {
				pgKeyList->AddKey(utKeyPrompt.Get(), FALSE, fSaveDecKey ? 0 : pCmdParam->dwBatch);
			}
		}
		else {
			dwReturn = WRN_CANCEL;
		}
	}
	else {
		// We know that hProgressWnd is part of a dialogue, and thus the parent of that
		// is what we want to have has parent for the pass phrase dialogue. This is not
		// neat, it's ugly, but the whole window handling needs massive clean-up anyway.
		(void)utKeyPrompt.Old(INF_ENTER_PASS, _T(""), GetParent(GetParent(pCmdParam->hProgressWnd)));
		if (utKeyPrompt.Get() != NULL) {
			// Test if we really should save the key here.
			BOOL fSaveEncKey = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveEncKey).GetDword();
			if (fSaveEncKey || pCmdParam->dwBatch != 0) {
				// This is may be a permanent allocation here.
				HEAP_CHECK_BEGIN(_T("CmdPromptKey(a)"), TRUE);
				pgKeyList->AddEncKey(utKeyPrompt.Get(), fSaveEncKey ? 0 : pCmdParam->dwBatch)->Key();
				HEAP_CHECK_END
			}
			BOOL fSaveDecKey = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValSaveDecKey).GetDword(FALSE);
			if (fSaveDecKey || pCmdParam->dwBatch != 0) {
				// This is may be a permanent allocation here.
				HEAP_CHECK_BEGIN(_T("CmdPromptKey(b)"), TRUE);
				pgKeyList->AddKey(utKeyPrompt.Get(), FALSE, fSaveDecKey ? 0 : pCmdParam->dwBatch);
				HEAP_CHECK_END
			}
		}
		else {
			dwReturn = WRN_CANCEL;
		}
	}
	return dwReturn;
}
//
//  Rename the input file to a unique, anonymous name.
//
DWORD
CmdAnonRename(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	// If necessary, set current directory
	CFileName fnCipher;
	fnCipher.Set(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str());

	HEAP_CHECK_BEGIN(_T("CmdAnonRename()"), 0)
		try {
		CFileIO utFileCipher;
		CHeaders utHeaders;
		utFileCipher.Open(fnCipher.Get(), FALSE, GENERIC_READ);

		utHeaders.Load(utFileCipher);

		// Get the low 32 bits of the HMAC.
		DWORD dwHmacLow = (DWORD)((DQWORD*)utHeaders.GetHMAC())->Lsb64();
		utFileCipher.Close();

		BOOL fOk;
		CFileName fnAnon = fnCipher;
		int nMaxTry = 25;   // Maximize retries to avoid possibility of looping.
		do {
			fnAnon.SetName(CPtrTo<TCHAR>(FormatSz(_T("%1!08X!"), dwHmacLow++)));
		} while (!(fOk = MoveFile(fnCipher.Get(), fnAnon.Get())) && GetLastError() == ERROR_ALREADY_EXISTS && --nMaxTry);
		CAssert(fOk).Sys(MSG_SYSTEM_CALL, _T("CmdAnonRename() [MoveFile()]")).Throw();
		SHChangeNotify(SHCNE_RENAMEITEM, SHCNF_PATH, fnCipher.Get(), fnAnon.Get());
	}
	catch (TAssert utErr) {
		utErr.Show();
		return utErr.LastError();
	}
	HEAP_CHECK_END
		return 0;
}

DWORD
CmdTestHaveKey(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	// These will auto-close upon destruction.
	CFileIO fioCipher;
	CHeaders Headers;

	fioCipher.Open(CFileName(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str()).Get(), FALSE, GENERIC_READ);

	Headers.Load(fioCipher);

	CPtrTo<TKey> pKeyEncKey;
	if (pgKeyList->TryOpen(&Headers, &pKeyEncKey, pCmdParam->dwBatch)) {
		return 0;
	}
	return WRN_NO_HAVE_KEY;
}
//
//	Output the id-tag, if any on standard output.
//
DWORD
CmdShowIdTag(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	try {
		CHeaders utHeaders;
		CFileIO utFileCipher;
		utFileCipher.Open(CFileName(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str()).Get(),
			FALSE,
			GENERIC_READ | GENERIC_WRITE);

		utHeaders.Load(utFileCipher);
		CPtrTo<TCHAR> szIdTag = utHeaders.GetIdTag();
		if (szIdTag) {
			if (pCmdParam->hStdOut == NULL || pCmdParam->hStdOut == INVALID_HANDLE_VALUE) {
				CAssert(FALSE, ERR_NO_STDOUT).App(ERR_NO_STDOUT).Throw();
			}
			int fd = _open_osfhandle((intptr_t)(pCmdParam->hStdOut), _O_TEXT | _O_APPEND);
			FILE* fp = _fdopen(fd, "w+t");
			(void)fprintf(fp, "%ls\n", (wchar_t*)szIdTag);
			(void)fflush(fp);
			// I don't think we should do any close here...
			//(void)fclose(fp);
			//(void)close(fd);
		}
		else {
			return ERR_NO_IDTAG;
		}

		utFileCipher.Close();				// Close (and delete)
	}
	catch (TAssert utErr) {
		// Hide progress window, if any.
		if (pCmdParam->hProgressWnd) {
			SendMessage(GetParent(pCmdParam->hProgressWnd), WM_APP, 0, 0);
		}
		utErr.File(ERR_FILE, pCmdParam->szParam1.c_str()).Show();
		return utErr.LastError();
	}
	return 0;
}
//
//  Start a brute force key search, and output the result in the registry and in
//  a dialog box, if any is ever found...
//
//  Now this might require a bit of consideration... Do I reduce the effectiveness
//  of Xecrets File by including code in the product to actually try to force it? Sounds
//  a bit counter-intuitive... But no, that's not the case. Because:
//
//  1 - We can only brute force, and only very small key spaces.
//  2 - You still need to write the actual bruteforce dll to generate keytries.
//  3 - The only reasonable way, except for silly passphrases, is to get very much
//      information from the legitimate owner of the data and the key, so the keyspace
//      is reduced to manageable proportions. You may approximate about 60 keys searched
//      per second per GHz Intel x86 CPU. This means you can search about 5 million keys
//      per 24 hour day per GHz. Digits and lowercase a-z with no system to it, 6 chars
//      length is about 2 billion keys. This means more than a years search on a 1GHz.
//      Add another character, and it adds up to about 50 years... Sure computers will
//      get faster, but just use a reasonable passphrase and you are safe.
//  4 - Now that you know that it exists - you have incentive to use strong passphrases,
//      instead of hoping that no-one had gone to the effort of doing this themselves.
//  5 - The whole point of Xecrets File is to be safe - if an unknown attacker can find your
//      passphrase with this brute force plug-in - You Are At Fault! This is because you
//      have choosen a ridiculously simple passphrase. Read the documentation on what is
//      a good passphrase. Do not trust security by obscurity. The only thing that should
//      protect your data is your passphrase. Nothing else. All is disclosed: the algorithms,
//      how they are applied, the full source code. All. Anyone with a bit of competence can
//      write a brute-force cracker on their own without the code below anyway. This is not
//      a back-door.
//  6 - This was written on request from a legitimate owner of data who has forgotten his
//      passphrase. Despite very detailed information about the passhprase, we're still
//      looking, a month later and with 2-4 machines working on it 24 hours a day.
//  7 - If you have a need for a brute force cracker and can convince me you are the legitimate
//      owner, and can supply me with detailed information on how the password likely is
//      constructed, I *may* attempt to write a custom key-try-generator for you, at a price.
//
DWORD
CmdBruteForce(CCmdParam* pCmdParam) {
	if (pCmdParam->szParam1.empty()) {
		return 0;
	}

	DWORD iRet = 0;
	size_t nProgress = 0;

	// Get hold of the various entry points in the brute force generator dll if it's there.
	HMODULE hAxBruteDll = LoadLibrary(CFileName().SetPath2ExeName().SetTitle((LPTSTR)szAxBruteDLL).Get());
	if (!hAxBruteDll) {
		return 0; // No brute force dll available, so just ignore and do nothing.
	}

	// A new instance, init with try and state
#pragma warning(push)
#pragma warning(disable:4191)
	void* (*pfNew)(char* szTry, int* state) = (void* (*)(char*, int*))GetProcAddress(hAxBruteDll, "New");
	// Step to next state in brute force strategy
	int(*pfStep)(void*) = (int(*)(void*))GetProcAddress(hAxBruteDll, "Step");
	// Get the current attempted string
	const char* (*pfTry)(void* ctx) = (const char* (*)(void*))GetProcAddress(hAxBruteDll, "Try");
	// Increment to the next string.
	int(*pfNext)(void* ctx) = (int(*)(void*))GetProcAddress(hAxBruteDll, "Next");
	// Free the context.
	void(*pfFree)(void* ctx) = (void(*)(void*))GetProcAddress(hAxBruteDll, "Free");
#pragma warning(pop)

	void* pCtx;
	auto_ptr<char> szCheckPoint;
	try {
		if (!pfNew || !pfStep || !pfTry || !pfNext || !pfFree) {
			CAssert(FALSE).App(MSG_INTERNAL_ERROR, _T("CmdBruteForce() [pfXXX == NULL]")).Throw();
		}

		CHeaders utHeaders;
		CFileIO utFileCipher;
		utFileCipher.Open(CFileName(pCmdParam->szParam1.c_str()).SetCurDir(pCmdParam->szCurDir.c_str()).Get(),
			FALSE,
			GENERIC_READ | GENERIC_WRITE);

		utHeaders.Load(utFileCipher);

		int state;
		if (!pCmdParam->szParam2.empty()) {
			std::string s = axpl::t2s(std::wstring(pCmdParam->szParam2));
			const char* szParamTry = s.c_str();
			unsigned checkPointSize = strlen(szParamTry) + 1;
			auto_ptr<char> szCheckPointTry(new char[checkPointSize]);
			ASSPTR(szCheckPointTry.get());

			szCheckPointTry.get()[0] = '\0';
			// \n is just a character that is not allowed in a passphrase, the intention
			// is to get all of the remaining string.
			sscanf_s(szParamTry, "%d:%[^\n]", &state, szCheckPointTry.get(), checkPointSize);

			pCtx = pfNew(szCheckPointTry.get(), &state);
		}
		else {
			pCtx = pfNew(NULL, 0);
		}
		if (!pCtx) {
			CAssert(FALSE).App(MSG_INTERNAL_ERROR, _T("CmdBruteForce() [pCtx == NULL]")).Throw();
		}
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

		// Initialize progress window, if any.
		HWND hProgressWnd = pCmdParam->hProgressWnd;
		if (hProgressWnd != NULL) {
			// Clear the operation text. Need to use SendMessage to cross process boundary
			SendMessage(GetDlgItem(GetParent(hProgressWnd), IDS_OPERATION), WM_SETTEXT, 0, (LPARAM)_T(""));

			// Start the visual wait timer, use send message to ensure sequence.
			SendMessage(GetParent(hProgressWnd), WM_APP + 2, 0, 0);
		}
		int iPercent = 0;
		do {
			const char* szTry = pfTry(pCtx);
			if (!szTry) {
				break; // Unexpected end of state or error.
			}
			size_t ccCheckPoint = strlen(szTry) + 20;
			szCheckPoint = auto_ptr<char>(new char[ccCheckPoint]); // 20 is for %d of state plus : and nul
			ASSPTR(szCheckPoint.get());

			sprintf_s(szCheckPoint.get(), ccCheckPoint, "%d:%s", state, szTry);
			if (nProgress++ % 5000 == 0) {
				CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValBruteForceCheck).SetSz(axpl::s2t(szCheckPoint.get()).c_str());
			}

			if (hProgressWnd) {
				if (nProgress % 100 == 0) {
					// Update window text if any progress
					SendMessage(GetDlgItem(GetParent(hProgressWnd), IDS_OPERATION), WM_SETTEXT, 0, (LPARAM)szTry);
					SendMessage(hProgressWnd, PBM_SETPOS, (WPARAM)(iPercent), 0);
				}
				// Test for cancel
				if (!GetWindowLongPtr(GetParent(hProgressWnd), GWLP_USERDATA)) {
					CAssert(FALSE).App(WRN_CANCEL).Throw();
				}
			}

			// Now generate the key, and try to open.
			CPtrTo<TKey> pKey = CSha1().GetKeyHash((unsigned char*)szTry, strlen(szTry));
			if (utHeaders.Open(pKey)) {
				MessageBox(NULL, axpl::s2t(szTry).c_str(), gszAxCryptExternalName, MB_OK);
				break;
			}
			// Increment to next password
		} while ((iPercent = pfNext(pCtx)) >= 0);
		utFileCipher.Close();				// Close (and delete)
	}
	catch (TAssert utErr) {
		// Hide progress window, if any.
		if (pCmdParam->hProgressWnd) {
			SendMessage(GetParent(pCmdParam->hProgressWnd), WM_APP, 0, 0);
		}
		utErr.File(ERR_FILE, pCmdParam->szParam1.c_str()).Show();
		iRet = utErr.LastError();
	}
	if (szCheckPoint.get()) {
		CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValBruteForceCheck).SetSz(axpl::s2t(szCheckPoint.get()).c_str());
	}
	if (pfFree) pfFree(pCtx);
	FreeLibrary(hAxBruteDll);
	return iRet;
}

/// \brief Key Wrap Speed Test
///
/// Step through a number of key wrap iterations until the
/// initiator signals us to stop. The purpose is to calibrate
/// the speed to set the key wrap iteration count.
/// The counter location is passed as pointer to an unsigned long
/// which we increment using the interlocked functions. When we
/// increment to zero, this indicates that the initiator wants
/// us to stop, so we do. We estimate the speed by simply doing
/// one block of AES-encryption, it's close enough. The key wrap
/// requires two blocks per iteration, but that's taken care of
/// by the caller, to keep this code more clean.
/// \param lpParameter unsigned long ptr where we keep count
/// \return Zero (no significance)
static DWORD WINAPI
AesSpeedTestThreadProc(LPVOID lpParameter) {
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
	TKey key;
	ZeroMemory(&key, sizeof key);
	CAes aes(&key, CAes::eECB, CAes::eDecrypt, CAes::eKey128Bits);

	TBlock block;
	ZeroMemory(&block, sizeof block);
	unsigned long uCount = 0;
	do {
		// Each key-wrap iteration
		aes.Xblock(&block, &block);
		if ((++uCount % 5000) == 0) {
			// Increase precision by yielding every now and then
			Sleep(1);
		}
	} while (InterlockedIncrement((volatile long*)lpParameter) > 0);
	// We terminate on negative or zero. Negative means overflow - are
	// really that fast? Zero means the caller has had enough.
	return 0;
}

/// \brief Test how many rounds of AES encryption we can do in a given time
///
/// The precision is very low, on a Windows system probably not better
/// than 20ms.
/// \param dwMilliseconds The testing period
/// \return The number of iterations recorded.
static
DWORD AesSpeedTest(DWORD dwMilliseconds) {
	static volatile long lCount = 0;
	DWORD dwThreadId = 0;

	// Create the thread suspended, on the theory that we then discount some
	// or most of the thread creation overhead.
	HANDLE hThread = CreateThread(NULL, 0, AesSpeedTestThreadProc, (LPVOID)&lCount, CREATE_SUSPENDED, &dwThreadId);
	CAssert(hThread != NULL).Sys().Throw();

	Sleep(10);
	CAssert(ResumeThread(hThread) != -1).Sys().Throw();
	Sleep(dwMilliseconds);

	// Ask for the other thread to stop.
	long lResult = InterlockedExchange(&lCount, -1);

	// Wait for the other thread to end too
	CAssert(WaitForSingleObject(hThread, 1000) == WAIT_OBJECT_0).Sys().Throw();
	CAssert(CloseHandle(hThread));

	// Return the maximum value if we got a wrap-around. Hooray Moores law is still at it!
	return lResult < 0 ? LONG_MAX : lResult;
}
//
// There are a number of registry settings that need to be set. The extension
// ".EXT" shall be associated with the "open" action.
// We must also establish a "universial" ContextMenuHandler for right-clicking.
// Assumption is that the dll and exe resides in the same directory and have the
// same name, except for extension .exe and .dll. We also assume we are running
// from the proper directory, i.e. we are installed in place.
//
// We check consistency and do not overwrite existing settings, you may call this as
// many times as you like without harm.
//
// So... For the ContextMenuHandler Shell Extension we need:
//
// [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved]
// gszAxCryptCLSID = szAxCryptProgDesc
//
// [HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\szAxCryptProgID]
// @ = gszAxCryptCLSID
//
// [HKEY_CLASSES_ROOT\CLSID\gszAxCryptCLSID]
// @ = szAxCryptProgID
//
// [HKEY_CLASSES_ROOT\CLSID\gszAxCryptCLSID\InprocServer32]
// @ = path-to-dll
// "ThreadingModel" = "Apartment"
//
// For the "open" action association with the ".EXT" extension (szAxCryptFileExtension)
//
// [HKEY_CLASSES_ROOT\szAxCryptFileExtension]
// @ = szAxCryptProgID
//
// [HKEY_CLASSES_ROOT\szAxCryptProgID]
// @ = szAxCryptProgDesc
//
// [HKEY_CLASSES_ROOT\szAxCryptProgID\DefaultIcon]
// @ = \"path-to-exe\", 0
//
// [HKEY_CLASSES_ROOT\szAxCryptProgID\CLSID]
// @ = gszAxCryptCLSID
//
// [HKEY_CLASSES_ROOT\szAxCryptProgID\PropertySheetHandlers\gszAxCryptCLSID]
//
// [HKEY_CLASSES_ROOT\szAxCryptProgID\shell\open\command]
// @ = \"path-to-exe\" \"%1\"
//
//  For global application options and state
//
//  [HKEY_CURRENT_USER\Software\Axon Data\AxCrypt] aka szAxCryptRegKey, szRegValServerMode
//  "ServerMode" = 0        ;!= 0 means we enter quiet server mode
//
// For the application state:
//
// [HKEY_CURRENT_USER\Software\Axon Data\AxCrypt] aka szAxCryptRegKey, szRegValEventLogLevel
// "EventLogLevel" = 0			; >0 means we log events, depending on the level of detail.
//
// [HKEY_CURRENT_USER\Software\Axon Data\AxCrypt] aka szAxCryptRegKey, szRegValNoUnsafeWipeWarn
// "NoShowUnsafeWipeWarn" = 0			; TRUE => Don't warn about unsafe wipes any more.
//
// [HKEY_CURRENT_USER\Software\Axon Data\AxCrypt] aka szAxCryptRegKey, szRegValSaveEncKey
// "SaveEncKey" = 0			; TRUE => Do save enc passphrases in the cache, and use as default.
//
// [HKEY_CURRENT_USER\Software\Axon Data\AxCrypt] aka szAxCryptRegKey, szRegValSaveDecKey
// "SaveDecKey" = 1			; TRUE => Do save dec passphrases in the cache.
//
DWORD
CmdInstallInRegistry(CCmdParam* pCmdParam) {
	const bool fOverwrite = false;          // Prepare for optional forced overwrite

	CFileName szPath2Exe; szPath2Exe.SetPath2ExeName();
	CFileName szPath2Dll(szPath2Exe); szPath2Dll.SetTitle(gszXecretsFileShellExtName);
	CFileName szPath2Ico(szPath2Exe); szPath2Ico.SetTitle(gszAxCryptIconName);

	// Create gszAxCryptCLSID - we need it unless we already have it
	if (!gszAxCryptCLSID || !*gszAxCryptCLSID) {
		GUID guid;
		CAssert(SUCCEEDED(CoCreateGuid(&guid))).Sys().Throw();

		LPOLESTR oleszCLSID;
		CAssert(SUCCEEDED(StringFromCLSID(guid, &oleszCLSID))).Sys().Throw();
		gszAxCryptCLSID = _tcsdup(oleszCLSID);
		CoTaskMemFree(oleszCLSID);
	}

	try {
		CRegistry utRegKey;

		// Then, Add the Approved key
		// [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved]
		// gszAxCryptCLSID = szAxCryptProgDesc
		LONG lRes;
		HKEY hRegKey = NULL;
		switch (lRes = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			_T("Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved"),
			0,
			KEY_WRITE,
			&hRegKey)) {
		case ERROR_ACCESS_DENIED:
		{
			// The user does not have permission to add a new value to this key. In this
			// case, a reasonable action would be to warn the user that some
			// application features will not be available unless an administrator
			// installs the application. If the shell extension is central to the
			// functioning of the application, tell the user that the install
			// can only be performed by an administrator, and stop the install.
			//
			// Before failing, we check if shell extension security is enforced. If it's not,
			// we silently ignore.
			DWORD dwEnforced = utRegKey.HKey(HKEY_CURRENT_USER).Value(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\EnforceShellExtensionSecurity")).GetDword(0);
			CAssert(dwEnforced == 0, lRes).Sys().Throw();
		}
		break;
		case ERROR_FILE_NOT_FOUND:
			// The key does not exist. This should only happen if setup is running
			// on Windows 95 instead of Windows NT, or if you are installing on an older
			// version of either operating system that does not have the new shell.
			// We ignore this.
			break;
		default:
		{
			// Now - let's make a CLSID for this installation instance.
			// This really doesn't do anyting! Bad thinking. Removed 1.5
			/// utRegKey.Root(HKEY_LOCAL_MACHINE).Key(gszAxCryptRegKey).Value(szRegValCLSID);

			// We don't check for existance of earlier install, we just overwrite.
			// Now let's actually do the work of defining the CLSID in the Approved section.
			// We do this regardless of fOverwrite, in the worst case it'll just duplicate the entry
			CRegistry().HKey(hRegKey).Value(gszAxCryptCLSID).SetSz(gszAxCryptProgDesc);
		}
		}

		// Next order of the day - fix the extension to use
		// First check if we already have it from the registry
		if (!gszAxCryptFileExt || !*gszAxCryptFileExt) {
			// If not - let's use the default extension
			if (pCmdParam->szParam1.empty()) {
				gszAxCryptFileExt = CopySz(szAxCryptDefFileExt);
			}
		}
		// We always override with the extension setting given on the command line
		if (!pCmdParam->szParam1.empty()) {
			gszAxCryptFileExt = CopySz(CFileName(pCmdParam->szParam1.c_str()).GetExt());
		}
		// Create or open the key
		utRegKey.Root(HKEY_LOCAL_MACHINE).CreateKey(gszAxCryptRegKey);
		// Actually set the file extension to use
		utRegKey.Value(szRegValFileExt).SetSz(gszAxCryptFileExt);

		//  [HKEY_CLASSES_ROOT] section
		utRegKey.Root(HKEY_CLASSES_ROOT);

		//  [HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\szAxCryptProgID]
		//  @ = szAxCryptCLSID
		utRegKey.CreateKey(_T("*\\shellex\\ContextMenuHandlers\\%1"), gszAxCryptProgID);
		utRegKey.Value(_T("")).SetSz(gszAxCryptCLSID);

		//  [HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\szAxCryptProgID]
		//  @ = gszAxCryptCLSID
		utRegKey.CreateKey(_T("Folder\\shellex\\ContextMenuHandlers\\%1"), gszAxCryptProgID);
		utRegKey.Value(_T("")).SetSz(gszAxCryptCLSID);

		//  [HKEY_CLASSES_ROOT\CLSID\gszAxCryptCLSID]
		//  @ = szAxCryptProgID
		utRegKey.CreateKey(_T("CLSID\\%1"), gszAxCryptCLSID);
		utRegKey.Value(_T("")).SetSz(gszAxCryptProgID);

		//  [HKEY_CLASSES_ROOT\CLSID\gszAxCryptCLSID\InprocServer32]
		//  @ = path-to-dll
		//  "ThreadingModel" = "Apartment"
		utRegKey.CreateKey(_T("CLSID\\%1\\InprocServer32"), gszAxCryptCLSID);
		utRegKey.Value(_T("")).SetSz(szPath2Dll.Get());
		utRegKey.Value(_T("ThreadingModel")).SetSz(_T("Apartment"));

		//
		// For the "open" action association with the ".EXT" extension (szAxCryptFileExtension)
		//
		//  [HKEY_CLASSES_ROOT\szAxCryptFileExtension]
		//  @ = szAxCryptProgID
		utRegKey.CreateKey(gszAxCryptFileExt);
		utRegKey.Value(_T("")).SetSz(gszAxCryptProgID);

		//  [HKEY_CLASSES_ROOT\szAxCryptProgID]
		//  @ = INF_FILE_TYPE_NAME	(Language dependant!)
		utRegKey.CreateKey(gszAxCryptProgID);
		utRegKey.Value(_T("")).SetSz(CMessage().AppMsg(INF_FILE_TYPE_NAME).GetMsg());

		//  [HKEY_CLASSES_ROOT\szAxCryptProgID\CLSID]
		//  @ = gszAxCryptCLSID
		utRegKey.CreateKey(_T("%1\\CLSID"), gszAxCryptProgID);
		utRegKey.Value(_T("")).SetSz(gszAxCryptCLSID);

		//  [HKEY_CLASSES_ROOT\szAxCryptProgID\DefaultIcon]
		//  @ = \"path-to-ico\", 0
		utRegKey.CreateKey(_T("%1\\DefaultIcon"), gszAxCryptProgID);
		utRegKey.Value(_T("")).SetSz(_T("%1,0"), szPath2Ico.Get());

		//  [HKEY_CLASSES_ROOT\szAxCryptProgID\shellex\PropertySheetHandlers\gszAxCryptCLSID]
		utRegKey.CreateKey(_T("%1\\shellex\\PropertySheetHandlers"), gszAxCryptProgID);
		CRegistry(utRegKey.GetHKey()).CreateKey(gszAxCryptCLSID);

		//  [HKEY_CLASSES_ROOT\szAxCryptProgID\shell\open\command]
		//  @ = \"path-to-exe\" \"%1\"
		utRegKey.CreateKey(_T("%1\\shell\\open\\command"), gszAxCryptProgID);
		utRegKey.Value(_T("")).SetSz(_T("\"%1\" \"%%1\""), szPath2Exe.Get());

		//  [HKEY_LOCAL_MACHINE]
		utRegKey.Root(HKEY_LOCAL_MACHINE).Key(gszAxCryptRegKey);

		utRegKey.Value(szRegValProductName).SetSz(gszAxCryptExternalName);

		utRegKey.Value(szRegValCLSID).SetSz(gszAxCryptCLSID);

		// The default is not to show the Activate Product menu
		utRegKey.Value(szRegValShowActivationMenu);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// "KeyWrapIterations" = 10000	; Current default.
		// Check how many rounds we can do in about 1/20th of a second. We need to keep some
		// margin if a user is using multiple keys, otherwise the try-and-find-key operation
		// may become annoyingly long.
		// Note that each key-wrap iteration is two AES operations.
		long lIterations = (AesSpeedTest(1000) / 2) / 20;
		lIterations -= lIterations % 1000;  // Make it an even thousand to ensure encrypor mach is not identifiable easily
		lIterations = lIterations < KEY_WRAP_ITERATIONS ? KEY_WRAP_ITERATIONS : lIterations;
		utRegKey.Value(szRegValKeyWrapIterations).SetDword(lIterations);

		//  [HKEY_CURRENT_USER] section
		utRegKey.Root(HKEY_CURRENT_USER);

		//  [HKEY_CURRENT_USER\Software\Axon Data\AxCrypt] aka szAxCryptRegKey, szRegValServerMode
		utRegKey.CreateKey(gszAxCryptRegKey);

		//  "ServerMode" = 0        ;!= 0 means we enter quiet server mode
		utRegKey.Value(szRegValServerMode);
		utRegKey.SetDword(fOverwrite ? 0 : utRegKey.GetDword(0));

		// "ServerErrorShellCmd" = "" -> means nothing happens here by default.
		utRegKey.Value(szRegValServerErrorShell);
		utRegKey.SetSz(fOverwrite ? _T("") : utRegKey.GetSz(_T("")));

		// "EventLogLevel" = 0			; >0 means we log events, depending on the level of detail.
		utRegKey.Value(szRegValEventLogLevel);
		utRegKey.SetDword(fOverwrite ? 0 : utRegKey.GetDword(0));

		// "NoShowUnsafeWipeWarn" = 0			; TRUE => Don't warn about unsafe wipes any more.
		utRegKey.Value(szRegValNoUnsafeWipeWarn);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// "SaveEncKey" = 0			; TRUE => Do save enc passphrases in the cache, and use as default.
		utRegKey.Value(szRegValSaveEncKey);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// "SaveDecKey" = 0			; TRUE => Do save dec passphrases in the cache.
		utRegKey.Value(szRegValSaveDecKey);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// "NoDecryptMenu" = 0		; TRUE => Do not show the decrypt menu in the shell extension.
		utRegKey.Value(szRegValNoDecryptMode);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// "CompressThreshold = COMPRESS_THRESHOLD. All expected compression ratios
		// higher or equal to this value leads to compression, otherwise it's skipped.
		utRegKey.Value(szRegValCompressLevel);
		utRegKey.SetDword(fOverwrite ? COMPRESS_THRESHOLD : utRegKey.GetDword(COMPRESS_THRESHOLD));

		// Enable rename menu by default.
		utRegKey.Value(szRegValNoRenameMenu);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// Disable try broken file by default.
		utRegKey.Value(szRegValTryBrokenFile);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// Only allow the proper extension for decryption by default.
		utRegKey.Value(szRegValAllowAnyExtension);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// Fast mode is not default.
		utRegKey.Value(szRegValFastModeDefault);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// Do not touch or create the Licensee/Signature entries during install. If this for some
		// reason is required, the installer must do this afterwards
		// "szRegValLicensee" = "" -> means no licensee entered by default.
		// "szRegValSignature" = "" -> means no signature entered by default.

		// Default is not to keep original sources time stamp on encryption.
		// This is a change for versions from 1.5.2.2. It makes more sense
		// semantically, since the file really is changed. Of course the original
		// time will still be restored always on decryption.
		utRegKey.Value(szRegValKeepTimeStamp);
		utRegKey.SetDword(fOverwrite ? FALSE : utRegKey.GetDword(FALSE));

		// Notify the shell about the new state of things
		SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST | SHCNF_FLUSHNOWAIT, 0, 0);
	}
	catch (TAssert utErr) {
		utErr.App(MSG_INSTALL_ERROR).Show();
	}
	return 0;
}

// Remove all that was installed in "Install in Registry". We do not duplicate that list here
// to make it easier to update. Please check above.
//
//  Uninstall should succeed as well as it can, so in case of error we continue anyway.
//
static HKEY hKeySettings[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

// Please remember to add keys here if they are added to the registry
static LPCTSTR szValues[] = {
	_T("NoUnsafeWipeWarn"),					// Compatibility with old version, so uninstall cleans it
	szRegValSaveEncKey,
	szRegValSaveDecKey,
	szRegValNoUnsafeWipeWarn,
	szRegValNoDecryptMode,
	szRegValServerMode,
	szRegValServerErrorShell,
	szRegValCompressLevel,
	szRegValNoRenameMenu,
	szRegValBruteForceCheck,
	szRegValTryBrokenFile,
	szRegValAllowAnyExtension,
	szRegValFastModeDefault,
	szRegValKeyFileInfo,
	szRegValKeyFileNotRemovable,
	szRegValKeyFileUseInfo,
	szRegValKeyFileNotEncrypt,
	szRegValSystemFolderWarn,
	szRegValWipePasses,
	szRegValKeepTimeStamp,
	// szRegValLicensee,			// Keep the licensee
	// szRegValSignature,			// Keep the signature
	szRegValShowActivationMenu,
	szRegValProductName,
	szRegValCLSID,
	szRegValFileExt,
	szRegValAfterNotifyName,
	szRegValBugReport,
	szRegValDocumentationName,
	szRegValDefaultLanguageId,
	szRegValKeyWrapIterations,
	szRegValUseEntropyPool,
	szRegValueEntropyPool,
	szRegValEventLogLevel,
	szRegValNotifyEmail,
	szRegValNotifyPreference,
	szRegValStartMenuFolder,
	szRegValExeFolder,
	szRegValInstallDir,
	szRegValInstallerLanguage,
	szRegValVersion,
	szRegValDefault,
	szRegValAllowPrograms,
};

DWORD
CmdRemoveFromRegistry(CCmdParam* pCmdParam) {
	DWORD dwLastError = ERROR_SUCCESS;
	try {
		// [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved]
		// gszAxCryptCLSID = szAxCryptProgDesc
		CRegistry utReg;
		try {
			utReg.Root(HKEY_LOCAL_MACHINE);
			utReg.Key(_T("Software\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved"));
			utReg.Value(gszAxCryptCLSID).DelValue();
		}
		catch (TAssert utErr) {
			dwLastError = utErr.App(MSG_UNINSTALL_ERROR).Show().LastError();
		}
		utReg.HKey(NULL);

		// [HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\szAxCryptProgID]
		try {
			utReg.Root(HKEY_CLASSES_ROOT);
			utReg.Key(_T("*\\shellex\\ContextMenuHandlers"));
			utReg.DelSubKeyRecurse(gszAxCryptProgID);
		}
		catch (TAssert utErr) {
			dwLastError = utErr.App(MSG_UNINSTALL_ERROR).Show().LastError();
		}
		utReg.HKey(NULL);

		// [HKEY_CLASSES_ROOT\Folder\shellex\ContextMenuHandlers\szAxCryptProgID]
		try {
			utReg.Root(HKEY_CLASSES_ROOT);
			utReg.Key(_T("Folder\\shellex\\ContextMenuHandlers"));
			utReg.DelSubKeyRecurse(gszAxCryptProgID);
		}
		catch (TAssert utErr) {
			dwLastError = utErr.App(MSG_UNINSTALL_ERROR).Show().LastError();
		}
		utReg.HKey(NULL);

		// [HKEY_CLASSES_ROOT\CLSID\gszAxCryptCLSID\InprocServer32]
		// [HKEY_CLASSES_ROOT\CLSID\gszAxCryptCLSID]
		if (gszAxCryptCLSID && *gszAxCryptCLSID) {
			try {
				utReg.Root(HKEY_CLASSES_ROOT);
				utReg.Key(_T("CLSID"));
				utReg.DelSubKeyRecurse(gszAxCryptCLSID);
			}
			catch (TAssert utErr) {
				dwLastError = utErr.App(MSG_UNINSTALL_ERROR).Show().LastError();
			}
		}
		utReg.HKey(NULL);

		// [HKEY_CLASSES_ROOT\szAxCryptFileExtension]
		try {
			CRegistry::DelSubHKeyRecurse(HKEY_CLASSES_ROOT, gszAxCryptFileExt);
		}
		catch (TAssert utErr) {
			dwLastError = utErr.App(MSG_UNINSTALL_ERROR).Show().LastError();
		}
		utReg.HKey(NULL);

		// [HKEY_CLASSES_ROOT\szAxCryptProgID\shell\open\command]
		// [HKEY_CLASSES_ROOT\szAxCryptProgID\CLSID]
		// [HKEY_CLASSES_ROOT\szAxCryptProgID\DefaultIcon]
		// [HKEY_CLASSES_ROOT\szAxCryptProgID]
		if (gszAxCryptProgID && *gszAxCryptProgID) {
			try {
				CRegistry::DelSubHKeyRecurse(HKEY_CLASSES_ROOT, gszAxCryptProgID);
			}
			catch (TAssert utErr) {
				dwLastError = utErr.App(MSG_UNINSTALL_ERROR).Show().LastError();
			}
		}
		utReg.HKey(NULL);

		// For the following:
		//
		// [HKEY_CURRENT_USER\Software\Axon Data\AxCrypt] aka HKCU\gszAxCryptRegKey
		// [HKEY_LOCAL_MACHINE\Software\Axon Data\AxCrypt] aka HKLM\gszAxCryptRegKey
		//
		// We only delete specific keys, and then only delete the keys if empty - we may want
		// to keep stuff between uninstall - re-install, specifically licensing information
		//
		// There is also the problem that we really should enumerate all users and find not only current user,
		// but that is currently overambtions - the worst that happens is that there are a few entries left for other
		// users. They do not hurt.

		// Iterate through all registry roots (HKLM, HKCU etc as defined) - in the future we may also
		// enumerate all users in the registry here.
		// Then, iterate through the set of all values used that should be deleted.
		// Finally, if the key is empty - delete it.
		for (int i = 0; i < sizeof hKeySettings / sizeof hKeySettings[0]; i++) {
			utReg.Root(hKeySettings[i]).Key(gszAxCryptRegKey);
			for (int j = 0; j < sizeof szValues / sizeof szValues[0]; j++) {
				try {
					utReg.Value(szValues[j]).DelValue();
				}
				catch (TAssert utErr) {
					dwLastError = utErr.App(MSG_UNINSTALL_ERROR).Show().LastError();
				}
			}
			utReg.Root(NULL);
			try {
				CRegistry::DelSubHKey(hKeySettings[i], gszAxCryptRegKey);
			}
			catch (TAssert) {
				// Ignore!
			}
		}
	}
	catch (TAssert utErr) {
		dwLastError = utErr.App(MSG_UNINSTALL_ERROR).Show().LastError();
	}
	return dwLastError;
}

DWORD CmdLicenseMgr(CCmdParam* pCmdParam) {
	// We know that hProgressWnd is part of a dialogue, and thus the parent of that
	// is what we want to have as the parent for the dialogue. This is not
	// neat, it's ugly, but the whole window handling needs massive clean-up anyway.
	ttstringpair spLicSig = GetLicenseeSignature(GetParent(GetParent(pCmdParam->hProgressWnd)));

	// If one or the other is empty - forget it.
	if (spLicSig.first.empty() || spLicSig.second.empty()) {
		return WRN_CANCEL;
	}
	return ERROR_SUCCESS;
}

DWORD CmdRegistration(CCmdParam* pCmdParam) {
	// We know that hProgressWnd is part of a dialogue, and thus the parent of that
	// is what we want to have as the parent for the dialogue. This is not
	// neat, it's ugly, but the whole window handling needs massive clean-up anyway.
	AskForRegistration(GetParent(GetParent(pCmdParam->hProgressWnd)), std::wstring(pCmdParam->szParam1));
	return ERROR_SUCCESS;
}
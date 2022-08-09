#pragma once
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
	XecretsFile.h					WinMain() and friends.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com			    2001					Initial

*/
#include	"CCryptoKey.h"
#include	"CCryptoHeap.h"
#include	"CCryptoRand.h"
#include	"CEntropy.h"
#include    "CConfigVerify.h"
#include    "../AxSigLib/CTrialMgr.h"
#include    "../AxSigLib/CLicMgr.h"
#include    "../AxSigLib/CRestrictMgr.h"

extern const unsigned char szPassphraseChars[];
//
extern const GUID guidAxCryptFileId;
//
extern CRITICAL_SECTION gLaunchAppCritical;
extern CRITICAL_SECTION gCurrentDirectoryCritical;
//
extern CPtrTo<CKeyList> pgKeyList;
//
extern HWND ghWnd;
extern HWND ghProgressWnd;
//
extern CPtrTo<CEntropy> pgEntropyPool;
extern CPtrTo<CCryptoRand> pgPRNG;
//
extern CConfigVerify* gpConfig;
extern CTrialMgr* gpTrialMgr;
extern CLicMgr* gpLicMgr;
extern CRestrictMgr* gpRestrictMgr;
//
extern DWORD MessageWaitForObject(HANDLE hObject, DWORD dwTimeout = INFINITE);
extern void ApplyTerms(const XNode* pRestrictXML);
//
//  Command request ID's
//
enum eRequestType {
	EN_OPEN = 1,    // Decrypt, decompress, launch, recompress and encrypt
	EN_ENCRYPTZC,   // Compress, encrypt as copy
	EN_ENCRYPTZCF,  // Compress, encrypt as copy, but fast (possibly unsafe).
	EN_ENCRYPTZ,    // Compress, encrypt an wipe original
	EN_ENCRYPTZF,   // Compress, encrypt an delete original (no wiping)
	EN_ENCRYPT,
	EN_WIPE,        // Wipe a file
	EN_WIPES,       // Wipe a file silently
	EN_DECRYPT,     // Decrypt, decompress and wipe original
	EN_DECRYPTF,    // Decrypt, decompress and delete original (no wiping)
	EN_DECRYPTC,    // Decrypt, decompress and retain original
	EN_DECRYPTCF,   // Decrypt, decompress and retain original, but fast (possibly insecure)
	EN_EXIT,        // Terminate master
	EN_INSTALL,     // Install in registry etc
	EN_UNINSTALL,   // Uninstall from registry etc
	EN_PSPTEST,     // Test the need for the psp library on NT
	EN_CLEARKEYS,   // Clear all keys in memory (or only a batch)
	EN_ADDKEYENC,   // Add an enc key to the cache (or for a batch)
	EN_ADDKEYDEC,   // Add a dec key to the cache (or for a batch)
	EN_ASKKEYENC,   // Prompt for an enc key to the cache (or for a batch)
	EN_ASKKEYDEC,   // Prompt for a dec key to the cache (or for a batch)
	EN_RENAME,      // Rename a file to an anonymous name
	EN_TESTHAVEKEY, // Test if we have the key for the file(s) in the cache.
	EN_SHOWTAG,		// Display the IdTag, if any, for files following.
	EN_GETPROCID,	// Get the primary process id
	EN_BRUTEFORCE,  // Attempt a brute-force attack to find a missing password
	EN_SFXENCNEW,                           ///< Encrypt to new SFX
	EN_SFXENCAPP,                           ///< Encrypt and append to SFX
	EN_MAKEKEYFILE,                         ///< Generate and save key-file
	EN_LICENSEMGR,                          ///< Invoke the license manager
	EN_GETTHREADEXIT,                        ///< Get the thread exit code from a worker thread.
	EN_REGISTRATION 						///< Invoke the registration dialog
};
//
//  Parameter information about the command to be executed.
//
class CCmdParam {
public:
	CCmdParam() { ZeroMemory(this, sizeof * this); }
	CCmdParam(CCmdParam& rhs) { *this = rhs; }
	CCmdParam& operator=(CCmdParam& rhs) {
		eRequest = rhs.eRequest;
		szParam1 = rhs.szParam1;
		szParam2 = rhs.szParam2;
		szIdTag = rhs.szIdTag;
		szCurDir = rhs.szCurDir;
		dwBatch = rhs.dwBatch;
		nWipePasses = rhs.nWipePasses;
		fIgnoreEncrypted = rhs.fIgnoreEncrypted;
		fIsEncKey = rhs.fIsEncKey;
		fSlowSafe = rhs.fSlowSafe;
		fRecurseDir = rhs.fRecurseDir;
		fAppend = rhs.fAppend;
		hProgressWnd = rhs.hProgressWnd;
		hForegroundWnd = rhs.hForegroundWnd;
		hStdOut = rhs.hStdOut;
		pDlgProgress = rhs.pDlgProgress;
		return *this;
	}

	enum eRequestType eRequest;     // What we want done...
	axpl::ttstring szParam1;        // A parameter
	axpl::ttstring szParam2;        // A second one..
	axpl::ttstring szIdTag;		    // An id-tag, if any given.
	axpl::ttstring szCurDir;        // Current directory of the caller.
	DWORD dwBatch;                  // The batch-id for this command.
	int nWipePasses;                  // The number of passes for wipe
	BOOL fIgnoreEncrypted;          // TRUE if we should not encrypt already encrypted.
	BOOL fIsEncKey;                 // TRUE if a key should be an encryption key
	BOOL fSlowSafe;                // TRUE if we should be slow and safe
	BOOL fRecurseDir;               // TRUE if we should descend recursively
	BOOL fAppend;                   // TRUE if we should append to the output file
	HWND hProgressWnd;              // The handle to a progress-bar window, if provided.
	HWND hForegroundWnd;            // Handle to the most recent foreground window.
	HANDLE hStdOut;				    // Handle to caller (secondary) stdout, if any.
	CProgressDialog* pDlgProgress;
};
//
//	Some useful stuff
//
#define	Min(a, b) ((a) < (b) ? (a) : (b))
#define Max(a, b) ((a) > (b) ? (a) : (b))
//
//  CAssert wrapper to be able to use code in other cases.
//
inline void CChkAss(bool fOk, const _TCHAR* sz) {
	CAssert(fOk).App(MSG_INTERNAL_ERROR, (_TCHAR*)sz).Throw();
}

/// \brief The size in bytes of a key-file generated by Xecrets File
const size_t gcbAxCryptKeyFile = sizeof "xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx" - 1;
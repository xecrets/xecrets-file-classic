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
	CKeyList.cpp					Key encrypting key handler and cache.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial
									2002-08-11              Rel 1.2

*/
#include	"StdAfx.h"
#include	"CCryptoKey.h"
#include	"Dialog.h"
#include	"CFile.h"
#include	"CCryptoRand.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CCryptoKey.cpp"
//
//	Prompt for a new key, return a handle to it, stored in the cache.
//	Return null if the user cancels or whatever.
//
CCryptoKey::CCryptoKey() {
	m_pNext = NULL;
	m_putKey = NULL;
	m_dwBatch = 0;
	m_fEncKey = false;  // Default is not an encryption key.
}

CCryptoKey::~CCryptoKey() {
	if (m_putKey != NULL) delete m_putKey;
	if (m_pNext != NULL) delete m_pNext;
}

CKeyList::CKeyList() {
	InitializeCriticalSection(&m_CritSect);
	m_pKeyRoot = NULL;
}

CKeyList::~CKeyList() {
	CCriticalSection utCritSect(&m_CritSect, TRUE);
	if (m_pKeyRoot != NULL) delete m_pKeyRoot;
}
//
//	Try all cached keys to open headers with.
//
//	The structure of headers is assumed to be loaded into memory at this point.
//
//	If the operation is successful, the headers are open for use on return.
//
//  A returned TKey * in *ppKeyEncKey must be deleted by the caller.
//
BOOL
CKeyList::TryOpen(CHeaders* pHeaders, TKey** ppKeyEncKey, DWORD dwBatch) {
	// We want to be alone for the duration.
	CCriticalSection utCritSect(&m_CritSect, TRUE);

	CCryptoKey* hKey = NULL;
	for (hKey = m_pKeyRoot; hKey != NULL; hKey = hKey->m_pNext) {
		if (((hKey->Batch() == 0) || (hKey->Batch() == dwBatch)) && (hKey->m_fEncKey == FALSE)) {
			if (pHeaders->Open(hKey->Key())) {
				*ppKeyEncKey = new TKey(*hKey->Key());
				ASSPTR(*ppKeyEncKey);
				return TRUE;
			}
		}
	}
	return FALSE;
}
//
//  Find a key, in a batch or global. No difference is made.
//  Search for either an encryption key, or a decryption key
//
CCryptoKey*
CKeyList::FindKey(TKey* putKeyBits, DWORD dwBatch, BOOL fEncKey) {
	CCriticalSection utCritSect(&m_CritSect, TRUE);
	CCryptoKey* putKey = m_pKeyRoot;
	while (putKey != NULL) {
		if ((putKey->Batch() == 0) || (putKey->Batch() == dwBatch)) {
			if ((*(putKey->Key()) == *putKeyBits) && (putKey->m_fEncKey == fEncKey)) {
				return putKey;
			}
		}
		putKey = putKey->m_pNext;
	}
	return NULL;
}
//
//	Add a new key to the cache.
//
CCryptoKey*
CKeyList::AddKey(TKey* putKeyBits, BOOL fEncKey, DWORD dwBatch) {
	// Keys are actually allocated 'forever', so let's keep that in mind.
	HEAP_CHECK_BEGIN(_T("AddKey()"), TRUE)

		CCryptoKey* putNewKey = new CCryptoKey;
	ASSPTR(putNewKey);

	TKey* putNewKeyBits = new TKey;
	ASSPTR(putNewKeyBits);

	*(putNewKey->m_putKey = putNewKeyBits) = *putKeyBits;
	putNewKey->m_dwBatch = dwBatch;
	putNewKey->m_fEncKey = fEncKey;

	CCriticalSection utCritSect(&m_CritSect, TRUE);
	putNewKey->m_pNext = m_pKeyRoot;

	return m_pKeyRoot = putNewKey;
	HEAP_CHECK_END
}
//
//  Add a new default encryption key to the cache. It is stored in the list,
//  and the previous key, if any, for this batch, is removed.
//  The pointer returned must not be
//  deallocated by the caller in any instance.
//
//  To add a temporary default encryption key for a batch, specify a
//  non-zero dwBatch.
//
CCryptoKey*
CKeyList::AddEncKey(TKey* pKeyBits, DWORD dwBatch) {
	CCryptoKey* pEncKey = m_pKeyRoot, ** pputPrevNext = &m_pKeyRoot;

	// First, ensure that the previous key, if any, is removed.
	CCriticalSection utCritSect(&m_CritSect, TRUE);

	while (pEncKey != NULL) {
		if ((pEncKey->Batch() == dwBatch) && pEncKey->m_fEncKey) {
			*pputPrevNext = pEncKey->m_pNext;
			pEncKey->m_pNext = NULL; // See destructor of CCryptoKey for explanation...
			delete pEncKey;

			pEncKey = *pputPrevNext;
		}
		else {
			pputPrevNext = &pEncKey->m_pNext;
			pEncKey = pEncKey->m_pNext;
		}
	}
	utCritSect.Leave();

	// Then just add the new encryption key
	return AddKey(pKeyBits, TRUE, dwBatch);
}
//
// Find default encryption key, if there is one. It will first look
// for a temporary key, then for a global key.
//
CCryptoKey*
CKeyList::FindEncKey(DWORD dwBatch) {
	// Scan the list for the default enc, if any, key.
	CCriticalSection utCritSect(&m_CritSect, TRUE);
	CCryptoKey* pEncKey = m_pKeyRoot;
	while (pEncKey != NULL) {
		if (pEncKey->Batch() == dwBatch) {
			if (pEncKey->m_fEncKey) {
				break;
			}
		}
		pEncKey = pEncKey->m_pNext;
	}
	utCritSect.Leave();

	// If we found one, return it.
	if (pEncKey) {
		return pEncKey;
	}

	// If we were looking for a temporary key, but did not find it,
	// let's check if there's a global one to use instead.
	if (dwBatch) {
		return FindEncKey(0);
	}

	return NULL;
}

void CKeyList::ClearKeys(DWORD dwBatch) {
	CCriticalSection utCritSect(&m_CritSect, TRUE);
	CCryptoKey* putKey = m_pKeyRoot, ** pputPrevNext = &m_pKeyRoot;
	while (putKey != NULL) {
		if (dwBatch == 0 || putKey->Batch() == dwBatch) {
			*pputPrevNext = putKey->m_pNext;
			putKey->m_pNext = NULL; // See destructor of CCryptoKey for explanation...
			delete putKey;

			putKey = *pputPrevNext;
		}
		else {
			pputPrevNext = &putKey->m_pNext;
			putKey = putKey->m_pNext;
		}
	}
}

CKeyPrompt::CKeyPrompt() {
	m_pKey = NULL;
}

CKeyPrompt::~CKeyPrompt() {
	if (m_pKey != NULL) delete m_pKey;
}
//
//	Prompt for a new, twice entered, key, hash it, and return a pointer to the key to use.
//
//	Return NULL if the user cancels.
//
CKeyPrompt&
CKeyPrompt::New(HWND hWnd) {
	char* szPassphrase = NULL;
	TCHAR* szKeyFileName = NULL;
	if (GetNewPassphrase(&szPassphrase, &szKeyFileName, hWnd)) {
		if (m_pKey != NULL) delete m_pKey;
		m_pKey = CSha1().GetKeyHash((BYTE*)(szPassphrase), strlen(szPassphrase), szKeyFileName);

		// Add some entropy to the PRNG, for what it's worth, even when it does not match!
		pgEntropyPool->Add((BYTE*)m_pKey, sizeof * m_pKey);
	}
	else {
		if (m_pKey != NULL) delete m_pKey;
		m_pKey = NULL;
	}
	delete[] szPassphrase;
	delete[] szKeyFileName;
	return *this;
}
//
//	Prompt for an existing passphrase, thus only ask for it once.
//
//	Return NULL if the user cancels
//
CKeyPrompt&
CKeyPrompt::Old(int iPrompt, LPCTSTR szFileName, HWND hWnd) {
	auto_ptr<char> szPassphrase(NULL);
	auto_ptr<TCHAR> szKeyFileName(NULL);

	if (GetPassphrase(iPrompt, szFileName, szPassphrase, szKeyFileName, hWnd)) {
		if (m_pKey != NULL) delete m_pKey;
		m_pKey = CSha1().GetKeyHash((BYTE*)(szPassphrase.get()), strlen(szPassphrase.get()), szKeyFileName.get());

		// Add some entropy to the PRNG, for what it's worth, even when it does not match!
		pgEntropyPool->Add((BYTE*)m_pKey, sizeof * m_pKey);
	}
	else {
		if (m_pKey != NULL) delete m_pKey;
		m_pKey = NULL;
	}
	return *this;
}
//
//	Return the actual pointer
//
TKey*
CKeyPrompt::Get() {
	return m_pKey;
}
#ifndef	_CCRYPTOKEY
#define	_CCRYPTOKEY
/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2020 Svante Seleborg/Axon Data, All rights reserved.

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
	CKeyList.h					Key encrypting key handler and cache.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
//
//	CKeyList.h - Basic Key Handling
//
//	Svante Seleborg
//
//	2001-10-07	Initial
//
//	This object is used to store, cache and generate 128-bit keys.
//
//	As we generate keys, we have a *big* problem generating entropy for this.
//	Whenever there is a chance, the rest of the code should call a global instance
//	of this class to add bits as they come available. The primary source is from
//	user supplied keys, which we use as key-encrypting keys. The basic theory here
//	is that the fundamental security lies in how many bits the user supplies. That
//	we use separate data encrypting keys is really just to foil some attacks based
//	on similar clear text or known clear text. The other reason is to have the
//	possibility to support multiple keys/file or split-master-key schemes etc.
//
//	All actual data of this class must be stored on the CryptoHeap in which we trust...
//
//
//	Helper mini-class, contains the cache of keys.
//
#include	"../XecretsFileCommon/Types.h"
#include	"CHeader.h"
#include    "../XecretsFileCommon/Utility.h"

class CKeyList;						// Forward declare for friend usage.

class CCryptoKey {
	friend CKeyList;
	CCryptoKey();
	~CCryptoKey();

	CCryptoKey* m_pNext;			// Simple linked list...
	TKey* m_putKey;					// The actual key, formed by hashing the string.
	DWORD m_dwBatch;                // Batch identifier that is valid for this key
	BOOL m_fEncKey;                 // True if is a default encrypting key.
public:
	TKey* Key() { return m_putKey; }
	DWORD Batch() { return m_dwBatch; }
};

class CKeyList {
	CCryptoKey* m_pKeyRoot;				// Pointer to the root of the cache chain in the safe heap
	CRITICAL_SECTION m_CritSect;
public:
	CKeyList();
	~CKeyList();
	BOOL TryOpen(CHeaders* pHeaders, TKey** ppKeyEncKey, DWORD dwBatch);	// Try to open using all keys in cache.
	CCryptoKey* FindKey(TKey* putKeyBits, DWORD dwBatch, BOOL fEncKey);       // Find this key in the cache, if it is there.
	CCryptoKey* FindEncKey(DWORD dwBatch);                      // Find default encryption key, if there is one.
	CCryptoKey* AddKey(TKey* putKeyBits, BOOL fEncKey, DWORD dwBatch);		// Add a new key to the cache.
	CCryptoKey* AddEncKey(TKey* putKeyBits, DWORD dwBatch);     // Add a new default encryption key to the cache.
	void ClearKeys(DWORD dwBatch);
};
//
//	Prompt for keys, new or old. The TKey* returned is only valid for
//	the lifetime of the CKeyPrompt-object. Use copy-semantics to save
//	longer
//
class CKeyPrompt {
	TKey* m_pKey;						// The key entered.
public:
	CKeyPrompt();
	~CKeyPrompt();
	CKeyPrompt& Old(int iPrompt, LPCTSTR szFileName, HWND hWnd = NULL);		// Prompt for an existing key
	CKeyPrompt& New(HWND hWnd = NULL);					// Prompt for a new, with verification
	TKey* Get();						// Get actual key, if any.
};
#endif _CCRYPTOKEY
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
	CSha1.cpp						Special purpose wrapper for Steve Reids SHA-1 code.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
#include	"StdAfx.h"
#include	"CSha1.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CSha1.cpp"

CSha1::CSha1() {
	m_putContext = new SHA1_CTX;
	ASSPTR(m_putContext);
}

CSha1::~CSha1() {
	delete m_putContext;
}

//
//	Hash a string and possibly the contents of a file,
//  and return the hash as a pointer to a key object
//
//	The key object must be deleted by the caller.
//
TKey*
CSha1::GetKeyHash(BYTE* poMsg, size_t iLen, TCHAR* szFileName) {
	TKey* putKeyHash = new TKey;
	ASSPTR(putKeyHash);

	SHA1Init(m_putContext);

	// Add the key-data to the hash.
	SHA1Update(m_putContext, poMsg, (unsigned int)iLen);

	// If we have a key-file as well, hash that in too. The idea is to
	// actually make it possible to have a key-file that is compatible
	// with a manually entered key.
	if (szFileName) {
		CFileIO fileKey;
		fileKey.Open(szFileName, FALSE, GENERIC_READ, FILE_SHARE_READ);

		// This must be a small memory buffer that does not get swapped to disk
		// Small because the OS won't allow us to lock much memory.
		const size_t cbBuf = 4096;
		BYTE* pbBuf = (BYTE*)VirtualAlloc(NULL, cbBuf, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		ASSAPI(pbBuf != NULL);
		ASSAPI(VirtualLock(pbBuf, cbBuf));

		size_t cb;
		do {
			cb = cbBuf;
			fileKey.ReadData(pbBuf, &cb);
			if (cb) {
				SHA1Update(m_putContext, pbBuf, (unsigned int)cb);
			}
		} while (cb);

		// Clear the memory, unlock it and release it
		ZeroMemory(pbBuf, cbBuf);
		ASSAPI(VirtualUnlock(pbBuf, cbBuf));
		ASSAPI(VirtualFree(pbBuf, 0, MEM_RELEASE));

		fileKey.Close();
	}

	// Get the final hash
	THash utHash;
	SHA1Final((BYTE*)&utHash, m_putContext);

	// Copy the key hash before returning a valid pointer.
	*putKeyHash = *utHash.KeyHash();
	return putKeyHash;
}
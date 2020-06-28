#ifndef	_CCRYPTOHEAP
#define	_CCRYPTOHEAP
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
	CCryptoHeap.h					A heap to be placed in a memory map

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial

*/
#include	"CFile.h"
//
//	CCryptoHeap.h - Reasonably secure memory storage for passwords
//
#define USED 1

// The overhead - the size of the block, including the overhead it-self.
// end of the chain is signalled by a zero.
typedef struct {
	size_t size;
} UNIT;

#ifdef	_DEBUG
class CHeapCheck;		// forward
#endif

class CCryptoHeap : public CFileIO {
#ifdef	_DEBUG
	friend CHeapCheck;
#endif	_DEBUG

	friend void* basenew(size_t);
	friend void operator delete(void*);

	CRITICAL_SECTION csThreadLock;
	UNIT* free;
	UNIT* heap;
	UNIT* compact(UNIT* p, size_t nsize);
	UNIT* reuse(UNIT* p, size_t nsize);
	BOOL* m_pfHeapValid;					// Static marker to ensure proper heap access
public:
	size_t m_stHeapLen;						// The length of the heap to allocate.
private:

	void Free(void* ptr);
	void* Alloc(size_t size);
	void Compact(void);

	HANDLE m_hMapping;			            // The mapping, which always maps the entire file
	DWORD m_nWipePasses;                    ///< We need to keep this around for the destructor
public:
	CCryptoHeap(size_t len, BOOL* pfHeapValid);
	~CCryptoHeap();
	void Init();							// Actually init and allocate it..
	size_t CurrentAlloc();
};

#endif	_CCRYPTOHEAP
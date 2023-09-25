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
	CCryptoHeap.cpp					A heap to be placed in a memory map and under full
									control as sensitive info is put there. Overload new
									and delete as well, unless _DEBUGHEAP is #defined.

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
//
//	A simple memory allocator for use with stuff that you want protected from the
//	paging/swap file such as passwords.
//
//	As you need to write/get a kernel mode driver to physically lock pages into memory,
//	(i.e. allocate from the non-paged pool) and this did not seem tasty to me, I
//	decided on another solution. If anyone one knows more than I - please let me know!
//
//	I use a memory mapped file view, and clear all memory as it is deallocated. Under
//	NTFS the file is properly protected, under other file systems I must simply trust
//	that other code is not running chancing to snoop the file in an unlucky moment.
//	This level is deemed ok - as a premise for the whole project is that it is not
//	for stored data secured on the local machine - use Encrypted File System or third
//	party virtual disks for that.
//
//	When a heap object is created, a temp file is created of the appropriate size.
//	When an item is free:d, the memory is zeroed before release to in the first place
//	minimize the risk of the data entering the private backing file.
//	When the object is destructed, the temp file is wiped before deletion as an
//	safety measure.
//
//	The assumption is that the file-mapping view will never be swapped to the
//	swap-file, thus I have full control. Once we exit, it should be safe as we
//	clean up.
//
//	The code is supposed to be thread safe as well.
//
//	Yes - it may still happen that data enters the file - the risk is low, and the
//	system is anyway open for attacks based on access to the local machine.
//
//	Credits to malkia@mindless.com who posted the original code to http://www.flipcode.com
//	Complaints to me - I did do some changes, but it sure saved me some time...
//
#include	"StdAfx.h"
#include	"memory.h"
#include	"CCryptoHeap.h"
#include	"CFileTemp.h"
#include    "../XecretsFileCommon/CRegistry.h"
//
//	The actual heap implementation - fairly standard stuff.
//
CCryptoHeap::CCryptoHeap(size_t len, BOOL* pfHeapValid) : CFileIO() {
	// We use an external, static, variable initialized to zero to ensure proper
	// stack usage. It get's tricky what with the complex order of things during
	// C++ startup. What we do know is that statics initialized to zero will
	// guaranteed be initialized before any code runs, thus we should be safe and
	// always use the proper stack using this as a helper. That we use an external
	// static is for the unlikely situation that more than one heap/process is
	// allocated.
	m_pfHeapValid = pfHeapValid;
	m_stHeapLen = len;
	m_hMapping = 0;
	m_nWipePasses = 1;
}

void
CCryptoHeap::Init() {
	// Ensure room for even multiple of UNIT's.
	m_stHeapLen = m_stHeapLen & ~(sizeof UNIT - 1);
	heap = 0;					// ensure that no allocs call the heap before it is ready...
	try {
		// Create the temporary file holding the protected heap.
		// This is debateable, it's not 100% clear from the documentation what FILE_FLAG_WRITE_THROUGH
		// really does, but it should be ok. Caching is still ok, but flushing should really flush.
		MakeTmp(CFileTemp().New().Get(), TRUE);

		// Initialize and enter critical section now
		InitializeCriticalSection(&csThreadLock);
		EnterCriticalSection(&csThreadLock);

		m_hMapping = CreateFileMapping(m_hFile, 0, PAGE_READWRITE, 0, m_stHeapLen, 0);
		// To enable debugging of this
		if (m_hMapping == 0) {
			CAssert(m_hMapping != 0).Sys(MSG_MAP_VIEW).Throw();
		}

		free = heap = (UNIT*)MapViewOfFile(m_hMapping, FILE_MAP_WRITE, 0, 0, m_stHeapLen);
		// To enable debugging of this
		if (heap == 0) {
			CAssert(heap != 0).Sys(MSG_MAP_VIEW).Throw();
		}

		// Set file size for wiping later. This should really be fixed - it's not a good idea to keep track
		// of the file size separately, it's a left over from previous versions.
		m_qwFileSize = m_stHeapLen;

		// One-big, free block, but save space for endmarker.
		free->size = heap->size = (DWORD)m_stHeapLen - sizeof UNIT;
		// Endmarker.
		((UNIT*)((char*)heap + heap->size))->size = 0;

		LeaveCriticalSection(&csThreadLock);

		m_nWipePasses = CRegistry(HKEY_CURRENT_USER, gszAxCryptRegKey, szRegValWipePasses).GetDword(1);
	}
	catch (TAssert utErr) {
		utErr.App(MSG_CRYPTO_HEAP_CONSTRUCT);
		FatalAppExit(0, utErr.GetMsg());
	}
	// Validate the heap.
	*m_pfHeapValid = TRUE;
}
//
//	Here wipe the memory, flush it, unmap, close mapping and file (and delete it).
//	The unmap etc is performed by the destructor of the base class.
//
CCryptoHeap::~CCryptoHeap() {
	if (*m_pfHeapValid) {
		try {
			EnterCriticalSection(&csThreadLock);		// Rather defensive...
			if (m_hMapping) {
				*m_pfHeapValid = FALSE;
				(void)memset(heap, 0, m_stHeapLen);		// Set heap to all zeroes
				// Then flush it to disk
				CAssert(FlushViewOfFile(heap, (DWORD)m_stHeapLen)).App(MSG_SYSTEM_CALL, _T("FlushViewOfFile() in ~CCryptoHeap()")).Throw();
				CAssert(UnmapViewOfFile(heap)).App(MSG_SYSTEM_CALL, _T("UnmapViewOfFile() in ~CCryptoHeap()")).Throw();
				CAssert(CloseHandle(m_hMapping)).App(MSG_SYSTEM_CALL, _T("CloseHandle() in ~CCryptoHeap()")).Throw();
				m_hMapping = 0;
			}
			heap = free = 0;
			LeaveCriticalSection(&csThreadLock);
			// We can't pick up the wipe passes from the registry, because the registry name strings have already been destructed...
			WipeTemp(0, m_nWipePasses);
		}
		catch (TAssert utErr) {
			utErr.App(MSG_CRYPTO_HEAP_DESTRUCT);
			FatalAppExit(0, utErr.GetMsg());
		}
	}
}
//
// Must only be executed in a critical section.
//
UNIT* CCryptoHeap::compact(UNIT* p, size_t nsize) {
	UNIT* best = 0;
	while (p->size) {
		if (p->size & USED) {
			best = 0;
		}
		else {
			if (best == 0) {
				best = p;
			}
			else {
				best->size += p->size;
				if (best->size < sizeof UNIT) {
					OutputDebugString(L"CCryptoHeap::compact() Attempt to set invalid size of free.");
					DebugBreak();
				}
			}
			if (best->size & USED) {
				OutputDebugString(L"CCryptoHeap::compact() Invalid heap state.");
				DebugBreak();
			}
			if (best->size >= nsize) {
				return best;
			}
		}
		if ((p->size & ~USED) < sizeof UNIT) {
			OutputDebugString(L"CCryptoHeap::compact() Found invalid block in heap.");
			DebugBreak();
		}
		p = (UNIT*)((char*)p + (p->size & ~USED));
	}
	return 0;
}

/// \brief Try to find an exact free block to reuse
UNIT* CCryptoHeap::reuse(UNIT* p, size_t nsize) {
	while (p->size) {
		if ((p->size & USED) == 0) {
			if (p->size == nsize) {
				p->size |= USED;
				if ((p->size & ~USED) < sizeof UNIT) {
					OutputDebugString(L"CCryptoHeap::reuse() Attempt to set invalid size.");
					DebugBreak();
				}
				if (p == free) {
					free = 0;
				}
				return (UNIT*)((char*)p + sizeof UNIT);
			}
		}
		if ((p->size & ~USED) < sizeof UNIT) {
			OutputDebugString(L"CCryptoHeap::reuse() Found invalid block in heap.");
			DebugBreak();
		}
		p = (UNIT*)((char*)p + (p->size & ~USED));
	}
	return 0;
}

void CCryptoHeap::Free(void* ptr) {
	if (ptr != 0) {
		if (!(ptr >= heap && ptr < (void*)((char*)heap + m_stHeapLen))) {
			OutputDebugString(L"CCryptoHeap::Free() Attempt to free memory not from this heap.");
			DebugBreak();
		}

		UNIT* p;

		EnterCriticalSection(&csThreadLock);

		p = (UNIT*)((char*)ptr - sizeof UNIT);
		if ((p->size & USED) == 0) {
			OutputDebugString(L"CCryptoHeap::Free() Attempt to free with an invalid memory pointer.");
			LeaveCriticalSection(&csThreadLock);
			DebugBreak();
		}
		p->size &= ~USED;
		if (p->size < sizeof UNIT) {
			OutputDebugString(L"CCryptoHeap::Free() Attempt to free with invalid size.");
			LeaveCriticalSection(&csThreadLock);
			DebugBreak();
		}
		memset(ptr, 0, p->size - sizeof UNIT); // Clear memory asap!

		LeaveCriticalSection(&csThreadLock);
	}
}

void* CCryptoHeap::Alloc(size_t size) {
	size_t fsize;
	UNIT* p;

	// I give up - let's do this here!
	if (size == 0) return 0;
	if (size >= 0x8000000) return 0;

	size_t st = CurrentAlloc();

	// Add size of the overhead block, and align to even multiple of such block.
	size += sizeof UNIT + sizeof UNIT - 1;
	size &= ~(sizeof UNIT - 1);

	EnterCriticalSection(&csThreadLock);
	p = reuse(heap, size);
	if (p != 0) {
		LeaveCriticalSection(&csThreadLock);
		return p;
	}
	if (free != 0 && (free->size & USED)) {
		OutputDebugString(L"CCryptoHeap::Alloc() Free is invalid.");
		LeaveCriticalSection(&csThreadLock);
		DebugBreak();
	}
	if (free == 0 || size > free->size) {
		free = compact(heap, size);
		if (free == 0) {
			LeaveCriticalSection(&csThreadLock);
			return 0;
		}
	}
	p = free;
	fsize = free->size;
	(void)memset(p, 0, size);	// Clear buffer
	if (fsize > size) {	// All allocs is in multiples of sizeof UNIT
		free = (UNIT*)((char*)p + size);
		if ((fsize - size) < sizeof UNIT) {
			OutputDebugString(L"CCryptoHeap::Alloc() Attempt to set invalid free size.");
			LeaveCriticalSection(&csThreadLock);
			DebugBreak();
		}
		free->size = fsize - size;
	}
	else {
		free = 0;
		size = fsize;
	}

	if (size < sizeof UNIT) {
		OutputDebugString(L"CCryptoHeap::Free() Attempt to alloc with invalid size.");
		LeaveCriticalSection(&csThreadLock);
		DebugBreak();
	}
	p->size = size | USED;
	LeaveCriticalSection(&csThreadLock);

	return (void*)((char*)p + sizeof UNIT);
}

void CCryptoHeap::Compact(void) {
	EnterCriticalSection(&csThreadLock);
	free = compact(heap, 0x7FFFFFFF);
	LeaveCriticalSection(&csThreadLock);
}

size_t
CCryptoHeap::CurrentAlloc() {
	EnterCriticalSection(&csThreadLock);
	UNIT* p = heap;
	size_t stCurrentAlloc = 0;
	while (p->size) {
		if (p->size & USED) {
			stCurrentAlloc += p->size & ~USED;
		}
		if ((p->size & ~USED) < sizeof UNIT) {
			OutputDebugString(L"CCryptoHeap::compact() Found invalid block in heap.");
			DebugBreak();
		}
		p = (UNIT*)((char*)p + (p->size & ~USED));
	}
	LeaveCriticalSection(&csThreadLock);
	return stCurrentAlloc;
}

#ifndef	_DEBUGHEAP
#ifdef	_DEBUG
__declspec(thread) size_t stAcceptedLeak = 0;

CHeapCheck::CHeapCheck(LPTSTR szFunc, BOOL fLeakOk) {
	m_szFunc = szFunc;
	// Save amount of alloc'd memory that is not already marked as permanent.
	m_stAlloc = tguiAlloc - stAcceptedLeak;
	m_fLeakOk = fLeakOk;
}

CHeapCheck::~CHeapCheck() {
	// Calculate (tguiAlloc - m_stAlloc) - (old m_stAcceptedLeak + new m_stAcceptedLeak)
	int stLeak = (int)(tguiAlloc - stAcceptedLeak - m_stAlloc);
	if (!m_fLeakOk && (stLeak > 0)) {
		TCHAR szLeak[20];
		(void)_stprintf_s(szLeak, sizeof szLeak / sizeof szLeak[0], _T("%d"), stLeak);
		CMessage().AppMsg(MSG_MEMORY_LEAK, szLeak, m_szFunc).ShowWarning(MB_OK);
	}
	stAcceptedLeak += stLeak; // Do not cascade leaks
}
#endif	_DEBUG
#endif	_DEBUGHEAP
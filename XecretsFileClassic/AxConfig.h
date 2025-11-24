#ifndef	_AXCONFIG
#define	_AXCONFIG
/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
	AxConfig.h						Some constants and version numbers etc

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
// Define to use VC's debug heap instead.
//#define _DEBUGHEAP

#define	MAX_PASSPHRASE_LEN	250
#define	KEY_WRAP_ITERATIONS	10000			// The standard says 6...
//
//	As the heap is one view of a memory mapped file, the MAX_VIEW_SIZE must be large
//	enough to hold the required heap.
//
//	The code will ensure that MAX_VIEW_SIZE is rounded down to a multiple of qwAllocationGranularity (usually 64k)
//
//	Use small values in debug, large values for effiency in release builds.
//
//	As of Beta 5, 2001-12-16, Each active instance of Xecrets File Classic requires approx 1K of secure heap.
//
#ifdef	_DEBUG
#define		MAX_VIEW_SIZE		(64*1024)
#define     COMPRESS_TEST_SIZE  (1024*1024)
#define		SECURE_HEAP_SIZE	(128*1024)
#else
#define		MAX_VIEW_SIZE		(2*1024*1024)
// Empirical tests have shown that this order of magnitude is necessary
// to get reasonable figures for media files and other compressed files.
#define     COMPRESS_TEST_SIZE  (1024*1024)
#define		SECURE_HEAP_SIZE	(1024*1024)
#endif	_DEBUG

// Consider compression worthwhile at x% and higher compression.
#define COMPRESS_THRESHOLD   20

// Define how frequently we insert a full flush, for robustness
#ifdef _DEBUG
#define ZLIB_FULL_FLUSH_SIZE 0x10000
#else
#define ZLIB_FULL_FLUSH_SIZE 0x10000
#endif

#if !defined(_DEBUGHEAP) && defined(_DEBUG)
extern __declspec(thread) size_t tguiAlloc;
#endif

#endif	_AXCONFIG
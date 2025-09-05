/*! \file
	\brief AxDecrypt - Stand-alone Xecrets File Classic-decrypter and self-extractor.

	@(#) $Id$

	A 'just-enough' bunch of routines that replace the equivalent things
	from the C Run Time Library.

	Copyright (C) 2004-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
*/
#include "StdAfx.h"
#ifdef AXLIB_ASSERT_FILE
#undef AXLIB_ASSERT_FILE
#endif
#define AXLIB_ASSERT_FILE "AxRtl.h"
///// \brief Exit the process with a return code.
/////
///// \param i The return code
//void exit(int i) {
//    ExitProcess(i);
//}
//
//extern "C" void __cdecl _exit (
//    int code
//    )
//{
//    exit(code);
//}
//
//extern "C" void __cdecl __crtExitProcess (
//    int status
//    ) {
//    ExitProcess(status);
//}
//
//extern "C" void __cdecl _amsg_exit (
//    int rterrnum
//    )
//{
//    exit(255);
//}
//
//extern "C" void __cdecl _initp_eh_hooks(void*);
//extern "C" void __cdecl _initp_heap_handler(void*);
//extern "C" void __cdecl _initp_misc_invarg(void*);
//extern "C" void __cdecl _initp_misc_purevirt(void*);
//extern "C" void __cdecl _initp_misc_rand_s(void*);
//extern "C" void __cdecl _initp_misc_winsig(void*);
//extern "C" void * __cdecl _encoded_null();
//
//extern "C" void __cdecl _init_pointers() {
//    void *enull = _encoded_null();
//
//    _initp_heap_handler(enull);
//    _initp_misc_invarg(enull);
//    _initp_misc_purevirt(enull);
//    _initp_misc_rand_s(enull);
//    _initp_misc_winsig(enull);
//    _initp_eh_hooks(enull);
//}
//

/// \brief Allocate memory from the heap.
///
/// malloc/calloc/realloc/new/new[]/free/delete/delete[] are all compatible in this mini-implementation
/// \param cb The number of bytes
/// \return A pointer to the memory block, or NULL
void* operator new(size_t cb) {
	return malloc(cb);
}

/// \brief Array new, minimal implementation (same as new).
///
/// malloc/calloc/realloc/new/new[]/free/delete/delete[] are all compatible in this mini-implementation
/// \param cb The number of bytes
/// \return A pointer to the memory block, or NULL
void* operator new[](size_t cb) {
	return malloc(cb);
}

/// \brief free a previously allocated memory block
///
/// malloc/calloc/realloc/new/new[]/free/delete/delete[] are all compatible in this mini-implementation
/// \param p Pointer to a memory block, or NULL (ignored)
extern "C" __declspec(noalias) void __cdecl free(void* p) {
#ifdef _DEBUG
	(void)::HeapValidate(::GetProcessHeap(), 0, p);
#endif
	if (p) {
		::HeapFree(::GetProcessHeap(), 0, p);
	}
}

/// \brief free a previously allocated memory block
///
/// malloc/calloc/realloc/new/new[]/free/delete/delete[] are all compatible in this mini-implementation
/// \param p Pointer to a memory block, or NULL (ignored)
void operator delete(void* p) {
	free(p);
}

/// \brief free a previously allocated memory block
///
/// malloc/calloc/realloc/new/new[]/free/delete/delete[] are all compatible in this mini-implementation
/// \param p Pointer to a memory block, or NULL (ignored)
void operator delete[](void* p) {
	free(p);
}

/// \brief Change the size of an allocated memory block, preserving data
///
/// malloc/calloc/realloc/new/new[]/free/delete/delete[] are all compatible in this mini-implementation
/// \param p Pointer to a previously allocated memory block, or NULL for first alloc
/// \param cb The number of bytes for the new memory block
/// \return A pointer to the memory block, or NULL
extern "C" __declspec(noalias) __declspec(restrict) void* __cdecl realloc(void* p, size_t cb) {
#ifdef _DEBUG
	(void)::HeapValidate(::GetProcessHeap(), 0, p);
#endif
	if (p) {
		return ::HeapReAlloc(::GetProcessHeap(), 0, p, cb);
	}
	else {
		// Realloc with NULL
		return malloc(cb);
	}
}

/// \brief Allocate a number of blocks, all zero-initialized
///
/// malloc/calloc/realloc/new/new[]/free/delete/delete[] are all compatible in this mini-implementation
/// \param nitems The number of items
/// \param cb The size of one item
/// \return A pointer to the memory block, or NULL
extern "C" __declspec(noalias) __declspec(restrict) void* __cdecl calloc(size_t nitems, size_t cb) {
#ifdef _DEBUG
	(void)::HeapValidate(::GetProcessHeap(), 0, NULL);
#endif
	return ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, nitems * cb);
}

/// \brief Allocate a block of memory
///
/// malloc/calloc/realloc/new/new[]/free/delete/delete[] are all compatible in this mini-implementation
/// \param cb The number of bytes to allocate
/// \return A pointer to the memory block, or NULL
extern "C" __declspec(noalias) __declspec(restrict) void* __cdecl malloc(size_t cb) {
#ifdef _DEBUG
	HANDLE h = ::GetProcessHeap();
	ASSAPI(h != NULL);
	(void)::HeapValidate(h, 0, NULL);
	void* vp = ::HeapAlloc(h, 0, cb);
	ASSPTR(vp);
	(void)::HeapValidate(h, 0, vp);
	return vp;
#else
	return ::HeapAlloc(::GetProcessHeap(), 0, cb);
#endif
}

/// \brief This is where we go when a pure function is called.
/// \return Always returns zero... Just a dummy.
extern "C" int __cdecl _purecall(void) {
	MessageBox(NULL, _T("Pure function called."), _T("AxDecrypt"), MB_OK | MB_ICONSTOP);
	return 0;
}

/// \brief Copy source buffer to destination buffer
///
/// memcpy() copies a source memory buffer to a destination memory buffer.
/// This routine does NOT recognize overlapping buffers, and thus can lead
/// to propogation.
/// For cases where propogation must be avoided, memmove() must be used.
/// Beware interaction with compiler switches for intrinsic functions etc
/// \param dst Pointer to destination buffer
/// \param src Pointer to source buffer
/// \param count Number of bytes to copy
/// \return Pointer to the destination buffer
void* __cdecl memcpy(void* dst, const void* src, size_t count) {
	void* ret = dst;

	while (count--) {
		*(char*)dst = *(char*)src;
		++(char*&)dst;
		++(char*&)src;
	}

	return ret;
}

/// \brief Sets "count" bytes at "dst" to "val"
///
/// Sets the first "count" bytes of the memory starting
/// at "dst" to the character value "val".
/// Beware interaction with compiler switches for intrinsic functions etc
/// \param dst Pointer to memory to fill with val
/// \param val Value to put in dst bytes
/// \param count Number of bytes of dst to fill
/// \return Pointer to destination buffer, with filled bytes
void* __cdecl memset(void* dst, int val, size_t count) {
	void* start = dst;

	while (count--) {
		*(char*)dst = (char)val;
		++(char*&)dst;
	}

	return start;
}

/// \brief Compare memory for lexical order
///
/// Compares count bytes of memory starting at buf1 and buf2 and find if
/// equal or which one is first in lexical order.
/// Beware interaction with compiler switches for intrinsic functions etc
/// \param buf1 Pointer to first memory section to compare
/// \param buf2 Pointer to second memory section to compare
/// \param count Length of sections to compare
/// \return &lt; 0 if buf1 &lt; buf2, 0 if buf1 == buf2, &gt; 0 if buf1 &gt; buf2
int __cdecl memcmp(const void* buf1, const void* buf2, size_t count) {
	if (!count) {
		return 0;
	}

	while (--count && *(char*)buf1 == *(char*)buf2) {
		++(char*&)buf1;
		++(char*&)buf2;
	}

	return *((unsigned char*)buf1) - *((unsigned char*)buf2);
}

/// \brief Search a string for a character
///
/// Searches a string for a given character, which may be the
/// null character '\0'.
/// Beware interaction with compiler switches for intrinsic functions etc
/// \param string String to search in
/// \param c Character to search for
/// \return Pointer to the first occurrence of c in string, NULL if c does not occur in string.
const char* __cdecl strchr(const char* string, int ch)
{
	while (*string && *string != (char)ch) {
		++string;
	}

	if (*string == (char)ch) {
		return (char*)string;
	}

	return NULL;
}

#if UINT_MAX != 0xffffffff
#error This module assumes 32-bit integers
#endif  /* UINT_MAX != 0xffffffff */

#if UINT_MAX != ULONG_MAX
#error This module assumes sizeof(int) == sizeof(long)
#endif  /* UINT_MAX != ULONG_MAX */

/// \brief Performs a rotate left on an unsigned integer.
///
/// Assumes that sizeof(int) == sizeof(long) == 4
/// Beware interaction with compiler switches for intrinsic functions etc
/// \param val Value to rotate
/// \param shift Number of bits to rotate by
/// \return Rotated value
unsigned long __cdecl _lrotl(unsigned long val, int shift) {
	shift &= 0x1f;
	val = (val >> (0x20 - shift)) | (val << shift);
	return val;
}

/// \brief Performs a rotate right on an unsigned integer
///
/// Assumes sizeof(int) == sizeof(long) == 4
/// Beware interaction with compiler switches for intrinsic functions etc
/// \param val Value to rotate
/// \param shift Number of bits to rotate by
/// \return Rotated value
unsigned long __cdecl _lrotr(unsigned long val, int shift) {
	shift &= 0x1f;
	val = (val << (0x20 - shift)) | (val >> shift);
	return val;
}

extern "C" void __cdecl main() {
}

/// \brief The main C Run Time Startup.
///
/// Parse the command line, get startup info and call WinMain
extern "C" void __cdecl

#if defined(UNICODE) || defined(_UNICODE)
WinMainCRTStartup(void)
#else
WinMainCRTStartup(void)
#endif

{
	char* lpszCommandLine = GetCommandLineA();

	// Skip past program name (first token in command line).

	if (*lpszCommandLine == '"') {
		// Check for and handle quoted program name
		lpszCommandLine++;	// Get past the first quote

		// Now, scan, and skip over, subsequent characters until  another
		// double-quote or a null is encountered
		while (*lpszCommandLine && (*lpszCommandLine != '"')) {
			lpszCommandLine++;
		}

		// If we stopped on a double-quote (usual case), skip over it.

		if (*lpszCommandLine == '"') {
			lpszCommandLine++;
		}
	}
	else {
		// First token wasn't a quote
		while (*lpszCommandLine > ' ') {
			lpszCommandLine++;
		}
	}

	// Skip past any white space preceeding the second token.

	while (*lpszCommandLine && (*lpszCommandLine <= ' ')) {
		lpszCommandLine++;
	}

	STARTUPINFO StartupInfo;
	StartupInfo.dwFlags = 0;
	GetStartupInfo(&StartupInfo);

	ExitProcess(WinMain(GetModuleHandle(NULL), NULL, lpszCommandLine,
		StartupInfo.dwFlags & STARTF_USESHOWWINDOW
		? StartupInfo.wShowWindow : SW_SHOWDEFAULT));
}
#pragma once
/*! \file
	\brief AxDecrypt - Stand-alone Xecrets File-decrypter and self-extractor.

	@(#) $Id$

	AxDecrypt - Stand-alone Xecrets File-decrypter and self-extractor.

	Copyright (C) 2004-2020 Svante Seleborg/Axon Data, All rights reserved.

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
*/

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "resource.h"
#include <memory>
using namespace std;

#include "../AxPipe/AxPipe.h"
#include "../AxPipe/CFileIO.h"
#include "../AxPipe/CPipeSHA1.h"
#include "../AxPipe/CPipeHMAC_SHA1.h"
#include "../AxPipe/CPipeFindSync.h"
#include "../AxPipe/CPipeInflate.h"
#include "../XecretsFileCommon/Types.h"
#include "../XecretsFileCommon/CAes.h"
#include "../XecretsFileCommon/CSubKey.h"
using namespace AxPipe;

/// \brief Load a string resource into an allocated string. Do delete.
extern _TCHAR* ALoadString(UINT uId, HMODULE hModule = NULL);

/// \brief Simple helper to XOR two memory blocks to a third.
/// Destination may be a separate block, or one of the two
/// source blocks.
/// \param dst Destination memory block
/// \param src1 One of the source memory blocks
/// \param src2 The other of the source memory blocks
/// \param len The length to XOR (all three buffers must be at least this large)
inline void
XorMemory(void* dst, void* src1, void* src2, size_t len) {
	while (len--) *((char*&)(dst))++ = *((char*&)src1)++ ^ *((char*&)src2)++;
}
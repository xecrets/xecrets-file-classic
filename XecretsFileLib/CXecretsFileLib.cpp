/*! \file
	\brief CXecretsFileLib.cpp - The private implementation class of the non-GUI Xecrets File Classic library

	@(#) $Id$

	CXecretsFileLib - Common non-GUI implementation class of the XecretsFileLib library for Xecrets File Classic.

	Copyright (C) 2005-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	YYYY-MM-DD              Reason
	2005-09-13              Initial
\endverbatim
*/
#include "stdafx.h"

#include "CXecretsFileLibMisc.h"

#include "Assert.h"
#define ASSERT_FILE "CXecretsFileLib.cpp"

/// \brief The Xecrets File GUID
/// Define the guid here xor 0xff, i.e. inverted, so we won't trig on it
/// when scanning for GUID in ourselves, looking for the appended .xxx-
/// files.
axcl::byte axcl::guidAxCryptFileIdInverse[16] = {
	0xc0 ^ 0xff, 0xb9 ^ 0xff, 0x07 ^ 0xff, 0x2e ^ 0xff, 0x4f ^ 0xff, 0x93 ^ 0xff, 0xf1 ^ 0xff, 0x46 ^ 0xff,
	0xa0 ^ 0xff, 0x15 ^ 0xff, 0x79 ^ 0xff, 0x2c ^ 0xff, 0xa1 ^ 0xff, 0xd9 ^ 0xff, 0xe8 ^ 0xff, 0x21 ^ 0xff
};
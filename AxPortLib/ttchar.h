#ifndef AXPORTLIB_TTCHAR_H
#define AXPORTLIB_TTCHAR_H
/*! \file
	\brief AxPortLib - Windows-like TCHAR definitions, but with double TT instead to differentiated.

	@(#) $Id$

	Copyright (C) 2008-2022 Svante Seleborg/Axantum Software AB, All rights reserved.

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
---
*/

#include "strcvt.h"

// A few Windows syntax-compatible definitions for Unicode/Non-Unicode builds
// Because it's not possible to be compatible with tchar.h for the definition of _T
// this code uses _TT instead.
#ifndef _TT
#ifdef _T
#define _TT _T
#else
#if defined(_UNICODE) || defined(UNICODE)
#define _TT(x) L ## x
#else
#define _TT(x) x
#endif // _UNICODE || UNICODE
#endif // _T
#endif // _TT

#endif
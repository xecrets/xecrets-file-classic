#ifndef AXSIGLIB_STDAFX_H
#define AXSIGLIB_STDAFX_H
/*! \file
	\brief AxSigLib - Short Elliptic Curve Digital Signature Algorithm et. al.

	@(#) $Id$

	Common includes for the library.

	Copyright (C) 2001-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

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

#include "targetver.h"

#ifdef _MSC_VER
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#endif

// TODO: reference additional headers your program requires here
#ifdef _MSC_VER
#include <windows.h>
#endif

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "AxSigLib.h"

#endif
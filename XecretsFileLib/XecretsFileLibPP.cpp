/*! \file
	\brief XecretsFileLibPP.cpp - C++ useage of XecretsFileLib, common declarations namespace axcl

	@(#) $Id$

	axcl - Common support library for Xecrets File

	Copyright (C) 2005-2022 Svante Seleborg/Axantum Software AB, All rights reserved.

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

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	YYYY-MM-DD              Reason
	2005-06-26              Initial (moved/restructured from Xecrets File)
\endverbatim
*/
#include "stdafx.h"

#include "XecretsFileLibPP.h"

namespace axcl {
	char* strdup(const char* s) { return strcpy(new char[strlen(s) + 1], s); }
#ifdef _UNICODE
	wchar_t* tstrcpy(wchar_t* d, const wchar_t* s) { return wcscpy(d, s); }
	wchar_t* tstrcat(wchar_t* d, const wchar_t* s) { return wcscat(d, s); }
	size_t tstrlen(const wchar_t* s) { return wcslen(s); }
	wchar_t* tstrdup(const wchar_t* s) { return wcscpy(new wchar_t[wcslen(s) + 1], s); }
#else
	char* tstrcpy(char* d, const char* s) { return strcpy(d, s); }
	char* tstrcat(char* d, const char* s) { return strcat(d, s); }
	size_t tstrlen(const char* s) { return strlen(s); }
	char* tstrdup(const char* s) { return strdup(s); }
#endif
}
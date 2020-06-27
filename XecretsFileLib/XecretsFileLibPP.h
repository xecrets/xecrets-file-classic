#ifndef XECRETSFILELIBPP_H
#define XECRETSFILELIBPP_H
/*! \file
	\brief XecretsFileLibPP.h - Include for C++ useage of XecretsFileLib, common declarations namespace axcl

	@(#) $Id$

	XecretsFileLib - C-callable library for Ax Crypt

	Copyright (C) 2005 Svante Seleborg/Axantum Software AB, All rights reserved.

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

#include <string>
#include <locale>
#include <string.h>

#include "Assert.h"
#define ASSERT_FILE "XecretsFileLibPP.h"

namespace axcl {
	// Modify according to compiler version. Include appropriate #ifdef's.
	typedef __int64 longlong;                   ///< Substitute for long long which is not always supported
	typedef unsigned __int64 ulonglong;         ///< Substitute for unsigned long long which is not always supported

	typedef unsigned char byte;                 ///< An 8-bit byte
	typedef long int32;                         ///< Signed 32-bit integer
	typedef unsigned long uint32;               ///< Unsigned 32-bit integer
	typedef __int64 int64;                      ///< Signed 64-bit integer
	typedef unsigned __int64 uint64;            ///< Unsigned 64-bit integer

	/// \brief Convert a wide Unicode string to a narrow Ansi string
	/// \param ws A wide string to convert
	/// \return A converted narrow string
	inline std::string w2s(const std::wstring& ws) {
		const std::ctype<wchar_t>& converter(std::use_facet<std::ctype<wchar_t> >(std::locale()));

		std::string s;
		s.reserve(ws.size());

		for (std::wstring::const_iterator it = ws.begin(); it != ws.end(); ++it) {
			s.push_back(converter.narrow(*it, '_'));
		}
		return s;
	}

	/// \brief Convert a narrow Ansi string to a wide Unicode string
	/// \param s A narrow string to convert
	/// \return A converted wide Unicode string
	inline std::wstring s2w(const std::string& s) {
		const std::ctype<wchar_t>& converter(std::use_facet<std::ctype<wchar_t> >(std::locale()));

		std::wstring ws;
		ws.reserve(s.size());

		for (std::string::const_iterator it = s.begin(); it != s.end(); ++it) {
			ws.push_back(converter.widen(*it));
		}
		return ws;
	}

	// To enable _UNICODE dependent usage of std::string/std::wstring
#pragma warning(disable:4995)       /* disable "name was marked as #pragma deprecated */
	template <class T> inline T* objdup(const void* p) { return static_cast<T*>(memcpy(new T, p, sizeof(T))); }
	template <class T> inline T* arrdup(const void* p, const size_t cItems) { return static_cast<T*>(memcpy(new T[cItems], p, cItems * sizeof(T))); }
	// Define this in the axcl:: namespace in a portable manner, ensuring that 'new' is used - not malloc
	extern char* strdup(const char* s);
#ifdef _UNICODE
	typedef std::wstring tstring;
	extern wchar_t* tstrcpy(wchar_t* d, const wchar_t* s);
	extern wchar_t* tstrcat(wchar_t* d, const wchar_t* s);
	extern size_t tstrlen(const wchar_t* s);
	extern wchar_t* tstrdup(const wchar_t* s);
	inline tstring s2t(const std::string& s) { return s2w(s); }
	inline tstring w2t(const std::wstring& ws) { return ws; }
	inline std::string t2s(const tstring& ts) { return w2s(ts); }
	inline std::wstring t2w(const tstring& ts) { return ts; }
#else
	typedef std::string tstring;
	extern char* tstrcpy(char* d, const char* s);
	extern char* tstrcat(char* d, const char* s);
	extern size_t tstrlen(const char* s);
	extern char* tstrdup(const char* s);
	inline ttstring s2t(const std::string& s) { return s; }
	inline ttstring w2t(const std::wstring& ws) { return w2s(ws); }
	inline std::string t2s(const ttstring& ts) { return ts; }
	inline std::wstring t2w(const ttstring& ts) { return s2w(ts); }
#endif
#pragma warning(default:4995)       /* restore "name was marked as #pragma deprecated */
} // namespace axcl

#endif XECRETSFILELIBPP_H
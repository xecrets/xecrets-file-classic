#ifndef AXPORTLIB_STRCVT_H
#define AXPORTLIB_STRCVT_H
/*! \file
	\brief AxPortLib - String conversion etc

	@(#) $Id$

	Copyright (C) 2008-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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

#include <string>
#include <locale>

namespace axpl {
	/// \brief Convert a wide Unicode string to a narrow Ansi string
	/// \param ws A wide string to convert
	/// \return A converted narrow string
	inline std::string ws2s(const std::wstring& ws) {
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
	inline std::wstring s2ws(const std::string& s) {
		const std::ctype<wchar_t>& converter(std::use_facet<std::ctype<wchar_t> >(std::locale()));

		std::wstring ws;
		ws.reserve(s.size());

		for (std::string::const_iterator it = s.begin(); it != s.end(); ++it) {
			ws.push_back(converter.widen(*it));
		}
		return ws;
	}
}
#endif
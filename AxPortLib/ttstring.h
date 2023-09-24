#ifndef AXPORTLIB_TTSTRING_H
#define AXPORTLIB_TTSTRING_H
/*! \file
	\brief AxPortLib - Unicode/Ansi dependent TT-style string utilities.

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

#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace axpl {
#if defined(_UNICODE) || defined(UNICODE)
	typedef std::wstring ttstring;

	inline ttstring s2t(const std::string& s) { return s2ws(s); }
	inline ttstring w2t(const std::wstring& ws) { return ws; }
	inline std::string t2s(const ttstring& ts) { return ws2s(ts); }
	inline std::wstring t2ws(const ttstring& ts) { return ts; }

#define ttstrcpy(d, s) wcscpy(d, s)
#define ttstrlen(s) wcslen(s)
#else
	typedef std::string tstring;

	inline ttstring s2t(const std::string& s) { return s; }
	inline ttstring w2t(const std::wstring& ws) { return ws2s(ws); }
	inline std::string t2s(const ttstring& ts) { return ts; }
	inline std::wstring t2ws(const ttstring& ts) { return s2ws(ts); }

#define ttstrcpy(d, s) strcpy(d, s)
#define ttstrlen(s) strlen(s)
#endif // _UNICODE || UNICODE

	/// \brief Small helper to do case-insensitive string comparison
	/// \param sL A string
	/// \param sR Another string
	/// \return true if equal, false if not
	inline bool TTStringCompareIgnoreCase(ttstring sL, ttstring sR) {
		std::transform(sL.begin(), sL.end(), sL.begin(), tolower);
		std::transform(sR.begin(), sR.end(), sR.begin(), tolower);
		return sL == sR;
	}

	typedef std::pair<ttstring, ttstring> ttstringpair;    ///< A pair of strings - useful
	typedef std::vector<ttstring> ttstringvector;          ///< A vector of strings - pretty useful too
	typedef std::map<ttstring, ttstring> ttstringmap;      ///< A map from string to string - too useful not to have...
	typedef std::vector<ttstringpair> ttstringpairvector;  ///< A vector of stringpairs - slightly more unusual
	typedef std::map<ttstring, int> ttstringintmap;        ///< A map from string to int.
} // namespace AxPortLib

#endif
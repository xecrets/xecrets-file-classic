#ifndef CRESTRICTMGR_H
#define CRESTRICTMGR_H
/*
	@(#) $Id$

	Xecrets File - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2004 Svante Seleborg/Axantum Software AB, All rights reserved.

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
	CRestrictMgr.h                    Keep track of effective restrictions
*/
#include <string>

using namespace std;

class CRestrictMgr {
	ttstringmap m_smRestrictions;             // The list of restrictions as strings.
public:
	CRestrictMgr() {}
	~CRestrictMgr() {
	}
	/// \brief Set a restriction - empty string means remove restriction.
	void Set(ttstring sRestrict, const ttstring sValue);
	/// \brief Check if there is a restriction with that name at all
	bool Has(ttstring sRestrict);
	/// \brief Get the restriction as a string. Must exist.
	const ttstring& GetStr(ttstring sRestrict);
	/// \brief Get the restriction interpreted as an integer. Must exist.
	int GetInt(ttstring sRestrict);
};

#endif
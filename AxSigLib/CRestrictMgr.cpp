/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

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
	CRestrictMgr.cpp                     Handle and validate licenses
*/
#include "stdafx.h"
#include "CRestrictMgr.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CRestrictMgr.cpp"

/// \brief Set a restriction - empty string means remove restriction.
void
CRestrictMgr::Set(ttstring sRestrict, const ttstring sValue) {
	transform(sRestrict.begin(), sRestrict.end(), sRestrict.begin(), tolower);

	if (sValue.empty()) {
		if (Has(sRestrict)) {
			m_smRestrictions.erase(sRestrict);
		}
	}
	else {
		m_smRestrictions[sRestrict] = sValue;
	}
}

/// \brief Check if there is a restriction with that name at all
bool
CRestrictMgr::Has(ttstring sRestrict) {
	transform(sRestrict.begin(), sRestrict.end(), sRestrict.begin(), tolower);
	return m_smRestrictions.find(sRestrict) != m_smRestrictions.end();
}

/// \brief Get the restriction as a string. Must exist.
const
ttstring&
CRestrictMgr::GetStr(ttstring sRestrict) {
	ASSCHK(Has(sRestrict), _T("Restriction must exist to get it!"));
	transform(sRestrict.begin(), sRestrict.end(), sRestrict.begin(), tolower);
	return m_smRestrictions[sRestrict];
}

/// \brief Get the restriction interpreted as an integer. Must exist.
int
CRestrictMgr::GetInt(ttstring sRestrict) {
	ASSCHK(Has(sRestrict), _T("Restriction must exist to get it!"));
	transform(sRestrict.begin(), sRestrict.end(), sRestrict.begin(), tolower);
	return atoi(t2s(m_smRestrictions[sRestrict]).c_str());
}
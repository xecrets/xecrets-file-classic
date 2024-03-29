#ifndef CDIALOGS_H
#define CDIALOGS_H
/*! \file
	\brief CDialogs.h - Various support for dialogs

	@(#) $Id$

*/
/*! \page License CDialogs.h - Various dialogs for XecretsFile2Go

	Copyright (C) 2005-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

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
*/
#include "../XecretsFileLib/CXecretsFileLib.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CDialogs.h"

class CPassphraseChars {
protected:
	axcl::CXecretsFileLib* m_pXecretsFileLib;

protected:
	static const char m_szPassphraseChars[];

public:
	CPassphraseChars(axcl::CXecretsFileLib* pXecretsFileLib) {
		m_pXecretsFileLib = pXecretsFileLib;
	}

public:
	CPassphraseChars() {
		m_pXecretsFileLib = NULL;
	}
};

#endif CDIALOGSWIN_H
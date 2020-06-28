#ifndef CCONFIGWIN_H
#define CCONFIGWIN_H
/*! \file
	\brief CConfigWin.h - Configuration information for XecretsFile2Go, Windows-specific

	@(#) $Id$

	XecretsFile2Go - Stand-Alone Install-free Xecrets File for the road.

	Windows specific additions to configuration data that may not have an exact equivalent in another
	environment, such as the concept of file extensions and version resource information.

	Copyright (C) 2006 Svante Seleborg/Axantum Software AB, All rights reserved.

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
	2006-01-15              Initial
\endverbatim
*/
#include "CConfig.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CConfigWin.h"

class CConfigWin : public CConfig {
private:
	static const axcl::tstring m_sEncryptedFileExtension;

protected:
	CConfigWin() {}

public:
	/// \brief Return the extension we use for encrypted files, with the "."
	/// \returns .xxx
	static const axcl::tstring& GetEncryptedFileExtension() {
		return m_sEncryptedFileExtension;
	}
};

#endif // CCONFIGWIN_H
#ifndef AXLIB_CWINVERSION
#define AXLIB_CWINVERSION
/*! \file
	\brief Determine Windows Version

	@(#) $Id$

	Copyright (C) 2009-2022 Svante Seleborg/Axon Data, All rights reserved.

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
	CWinVersion.h

	E-mail                          YYYY-MM-DD              Reason
	software@axantum.com             2009-08-19              Initial

*/
namespace AxLib {
	enum WINVERSION {
		WINXX,
		WIN95,
		WIN98,
		WINME,
		NT3,
		NT4,
		WIN2K,
		WINXP,
		W2003,
		WINVISTA,
		WIN2008,
		WIN7,
		WINHS,
		WIN8,
		WIN2012,
		WIN10,
		WIN2016,
		X64 = 128,
	};

	/// \brief Determine Windows Version
	///
	/// Determine Windows Version and bit-ness etc.
	class IWinVersion {
	public:
		static IWinVersion* New();
		virtual int GetVersion() = 0;
		virtual ~IWinVersion() = 0;
	};
}
#endif
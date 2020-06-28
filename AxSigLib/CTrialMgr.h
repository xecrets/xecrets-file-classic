#ifndef CTRIALMGR_H
#define CTRIALMGR_H
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
	CTrialMgr.h                    Manage trial use counters etc.
*/
#include "AxSigLib.h"
#include <wincrypt.h>

#include <string>

using namespace std;

/// \brief Handle use counts etc.
/// A handler of small counts in a somewhat obscure manner. The idea is that for trial software
/// you need to keep track of a few counters, with small values - typically the number of uses
/// or the number of days since installation, or the number of days used etc. This class implements
/// this in a way that should work even when there is no user profile, such as when running as a
/// service or in a terminal server environment with mandatory profiles. This puts severe restrictions
/// on what we can do. At this time, we try to create and write a hidden file with a non-obvious name
/// in the %TEMP% or %TMP% directory. If that fails, we silently do nothing. If someone deletes the
/// file, what happens is we revert to the start of the trial period. The actual counter is encoded as
/// increments in the 'modify' time of the file, relative the 'create' time.
class CTrialMgr {
	ttstring m_sProgram;                      ///< The program that we're counting for.
	std::string m_CounterFileName;                 ///< The obfuscated name of the file.
	ttstring m_TempPath;

public:
	/// \brief Make an interface object to the trial counters
	CTrialMgr(const ttstring& sProgram);
	/// \brief Clean up and release handle to provider if any
	~CTrialMgr();
	/// \brief Get the trial counter as it is now
	int Get(const ttstring& sCounterName = _TT("A"), int iMax = 100);

	/// \brief Increment the trial counter and return the new one, maximized by iMax+1
	int Increment(int iMax = -1, const ttstring& sCounterName = _TT("A"));
	/// \brief Clear this trial counter, when we have got a license for example.
	void Clear(const ttstring& sCounterName = _TT("A"));
};
#endif
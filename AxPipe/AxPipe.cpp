/*! \file
	\brief Main class implementation, AxPipe::CSource, AxPipe::CSink, AxPipe::CPipe, AxPipe::CFilter, AxPipe::CJoin, AxPipe::CSplit

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2022 Svante Seleborg/Axon Data, All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:axpipe@axondata.se and http://axpipe.sourceforge.net

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	AxPipe.cpp                      Main class implementation

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-11-23              Initial
\endverbatim
*/
#include "stdafx.h"
using namespace AxPipe;

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "AxPipe.cpp"

namespace AxPipe {
	/// Used to keep track of thread fiber-status for the pull-filter mode classes.
	DWORD AxPipe::dwTlsIndex;
	/// Ensure that global data is initialized once, and only once.
	volatile long AxPipe::nGlobalInit;

	/// ERROR_CODE_GENERIC - for most errors, one string argument.
	const _TCHAR* ERROR_MSG_GENERIC = _T("AxPipe:: %s");
	/// ERROR_CODE_INTERNAL - for fatal internal errors, one string argument.
	const _TCHAR* ERROR_MSG_INTERNAL = _T("AxPipe:: Internal error %s");
	/// ERROR_CODE_NOTOPEN - Sequence error in operations - need open first.
	const _TCHAR* ERROR_MSG_NOTOPEN = _T("AxPipe:: Pipe not Open");
}
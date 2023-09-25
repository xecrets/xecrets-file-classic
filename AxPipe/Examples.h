#pragma once
/*! \file
	\brief Copying examples and patterns, CFilterNop, CJoinInterleave

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2023 Svante Seleborg/Axon Data, All rights reserved.

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

	Why is this framework released as GPL and not LGPL?
	See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	Examples.h                      Copying examples and patterns

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-11-23              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "Examples.h"

/// \brief A sample CFilter derived class that just let's the data through
///
/// Use this class as an example to derive further from, modifying the InFilter()
/// implementation as appropriate.
class CFilterNop : public AxPipe::CFilter {
protected:
	void InFilter();                        ///< A no-operation implementation of InFilter()
};

/// \brief Sample CJoin
///
/// This is a copying pattern example to use to create CJoin based
/// derivations. It reads segments of data from a number of streams
/// and interleaves them in the output. It's actually rather uncontrolled,
/// since the size of the segments provided etc is up to respective stream
/// but this is just a basic template.
class CJoinInterleave : public AxPipe::CJoin {
public:
	/// \brief The overridden In()
	AxPipe::CSeg* In();
};

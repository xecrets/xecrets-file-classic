/*! \file
	\brief Implementation of various patterns and examples to start with

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
	Examples.cpp                    Implementation of various patterns and examples to start with

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"
#include "Examples.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "Examples.cpp"

/// \brief A dummy filter that does nothing, but provides the basic loop
///
/// Do the real stuff here. Use Open(), Read(), Pump() and Close().
/// This is a copying sample. It does nothing, but demonstrates possible techniques.
/// Always initialize everything at start - you may be called any number of times.
void CFilterNop::InFilter() {
	AxPipe::CSeg* pInSeg;
	size_t cbIn;
	Open();
	// End of this stream is signalled by NULL
	while (pInSeg = Read(), (pInSeg && (cbIn = pInSeg->Len()))) {
		// We're not guaranteed to get an output segment of the required
		// size, so we must loop here.
		while (cbIn) {
			AxPipe::CSeg* pOutSeg = GetSeg(cbIn);

			if (!pOutSeg) {
				return;         // Error of some kind
			}
			// This might be a good place to do something...
			memcpy(pOutSeg->PtrWr(), pInSeg->PtrRd(), pOutSeg->Len());

			cbIn -= pOutSeg->Len();
			Pump(pOutSeg);
		}
		// We're done with the inbuffer, let it go.
		pInSeg->Release();
	}
	Close();
	// This might be a good place to flush, if there's anything to flush. There's
	// no explicit Flush() method for pull-style filters. When returning, you should
	// be ready for a new call to InFilter().
}

/// \brief The overridden In()
///
/// This is what must be overriden to actually do anything. The following
/// is a sample that picks data from one, and then the other, until end
/// of all streams is reached.
/// \return A segment from each input stream in round-robin fashion until all are empty.
AxPipe::CSeg*
CJoinInterleave::In() {
	static int nThisIx = 0;
	int nStartIx = nThisIx;
	do {
		if (!StreamEmpty(nThisIx)) {
			AxPipe::CSeg* pSeg = StreamSeg(nThisIx);
			if (pSeg && pSeg->Len()) {
				// This is where you would do something with the data before passing it on
				// by returning a segment. At this point you know which stream the data
				// came from.
				return pSeg;
			}
		}
		// Next stream
		nThisIx = StreamIx(nThisIx + 1);
	} while (nThisIx != nStartIx);

	// Only signal end of stream when all streams are empty.
	return new AxPipe::CSeg;
}
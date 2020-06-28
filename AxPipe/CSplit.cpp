/*! \file
	\brief Implementation of AxPipe::CSplit base class for Y-split

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2020 Svante Seleborg/Axon Data, All rights reserved.

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
	CSplit.cpp                      Implementation of CSplit base class for Y-split

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CSplit.cpp"

namespace AxPipe {
	/// This is called by the base class destructor.
	/// Destruct the chain, waiting for parts of it to finish and skipping
	/// parts that should not be auto-destructed. It will call delete for those
	/// sections that are marked for auto-destruction. We need to override the
	/// the base class definition, since we're not using m_pSink to point to
	/// the rest of the chain.
	void
		CSplit::DestructSink() {
		// Here we do a safety first, so we can be called even if it's not
		// properly constructed.
		if (m_pLeft) {
			m_pLeft->WorkExitWait();
			delete m_pLeft;
		}
		if (m_pRight) {
			m_pRight->WorkExitWait();
			delete m_pRight;
		}
		m_pLeft = m_pRight = NULL;
	}
	/// \brief Send the same segment down both left and right legs of the split
	/// \param pSeg Pointer to a segment to send
	void
		CSplit::PumpSplit(CSeg* pSeg) {
		pSeg->AddRef();
		m_pLeft->OutPump(pSeg);
		m_pRight->OutPump(pSeg);
	}

	/// \brief Construct and initialize the member variables.
	CSplit::CSplit() {
		m_pLeft = NULL;
		m_pRight = NULL;
	};

	/// Normally append a sink, but not valid for CSplit
	/// \param pSink Pointer to an instance of a CSink derived object.
	/// \param fAutoDeleteSink true if the object should be delete'd when the member upstream is delete'd.
	void
		CSplit::AppendSink(CSink* pSink, bool fAutoDeleteSink) {
		pSink; //Dummy for C4100
		fAutoDeleteSink; //Dummy for C4100
		SetError(ERROR_CODE_GENERIC, _T("Use Init() for CSplit"));
	}

	/// Synchronize all work downstream, ensuring
	/// that there is no work in progress.
	void
		CSplit::Sync() {
		WaitForIdle();
		m_pLeft->Sync();                    // Wait for the rest of the pipe too.
		m_pRight->Sync();                   // Wait for the rest of the pipe too.
	}

	/// \brief Initialize split with left and right pointers to pipes.
	///
	/// The provided pointers to CPipe are always auto delete'd. Errors occurring
	/// in either of the two splits are aggregated backwards to the original CSource.
	/// \param pLeft Pointer to left pipe, does not start with a  CPipe, but ends with a CSink
	/// \param pRight Pointer to right pipe, does not start with a  CPipe, but ends with a CSink
	/// \return A pointer to 'this' CSplit.
	CSplit*
		CSplit::Init(CPipe* pLeft, CPipe* pRight) {
		(m_pLeft = pLeft)->CError::Init(this);
		(m_pRight = pRight)->CError::Init(this);
		return this;
	}
	/// \brief Send the same segment downstream to both parts of the split.
	/// \see CPipe::Out()
	void
		CSplit::Out(CSeg* pSeg) {
		PumpSplit(pSeg);
	}

	/// \brief Send the same special segment downstream to both parts of the split.
	/// \return false. Never indicate propagation, as this object in many ways is a sink.
	/// \see CPipe::OutSpecial()
	bool
		CSplit::OutSpecial(CSeg* pSeg) {
		PumpSplit(pSeg);
		return false;
	}

	/// \brief Send a flush signal downstream to both parts of the split.
	///
	/// \return false. Never indicate propagation, as this object in many ways is a sink.
	/// \see CPipe::OutFlush()
	bool
		CSplit::OutFlush() {
		PumpSplit((new CSeg)->SetType(eSegTypeFlush));
		return false;
	}

	/// \brief Send a close signal downstream to both parts of the split.
	///
	/// Never indicate propagation, as this object in many ways is a sink.
	/// \see CPipe::OutClose()
	bool
		CSplit::OutClose() {
		PumpSplit((new CSeg)->SetType(eSegTypeClose));
		return false;
	}

	/// \brief Send an open signal downstream to both parts of the split.
	///
	/// Never indicate propagation, as this object in many ways is a sink.
	/// \see CPipe::OutOpen()
	bool
		CSplit::OutOpen() {
		PumpSplit((new CSeg)->SetType(eSegTypeOpen));
		return false;
	}
};
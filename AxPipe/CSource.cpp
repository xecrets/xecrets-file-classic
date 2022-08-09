/*! \file
	\brief Implementation of AxPipe::CSource, base class for sources

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
	CSource.cpp                     Implementation of CSource, base class for sources

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CSource.cpp"

namespace AxPipe {
	/// When a CSource get's destructed, we ensure that Plug() is called, so
	/// we know that we really can destruct it safely without any other threads
	/// referencing it.
	CSource::~CSource() {
		Plug();                             // Safety first Plug(), is ok to call many times.
	}
	/// \brief Append a section by pointer with auto deletion.
	/// \param pSink Pointer to an instance of a CSink derived object.
	/// \return A pointer to 'this' CSource
	/// \see CPipe::Append(CSink *)
	CSource*
		CSource::Append(CSink* pSink) {
		CPipe::Append(pSink);
		return this;
	}

	/// \brief Append a section by reference.
	/// \param sink Reference to an instance of a CSink derived object.
	/// \return A pointer to 'this' CSource
	/// \see CPipe::Append(CSink&)
	CSource*
		CSource::Append(CSink& sink) {
		AppendSink(&sink, false);
		return this;
	}

	/// \brief Open the source and possibly propagate downstream
	///
	/// All other sections Open() will only open the stream downstream of the
	/// current object, but since this is a CSource, we first call our own OutOpen(),
	/// then propagate if OutOpen() indicates we should. Override OutOpen() to
	/// implement stream open.
	/// \return A pointer to 'this' cSource.
	CSource*
		CSource::Open() {
		if (!m_fIsOpen) {
			OutPump((new CSeg)->SetType(eSegTypeOpen));
			m_fIsOpen = true;
		}
		return this;
	}

	/// \brief Close the source and possible propagate downstream
	///
	/// This will first call OutClose(), then propagate the signal downstream if
	/// OutClose() indicates we should by returning true. Override OutClose() to
	/// implement a closing of the stream.
	CSource*
		CSource::Close() {
		if (m_fIsOpen) {
			OutPump((new CSeg)->SetType(eSegTypeClose));
			m_fIsOpen = false;
		}
		return this;
	}

	/// \brief Drain the pipe until In() says we're empty for now.
	/// \return A pointer to 'this' CSource to allow the notation: pmySource->Drain()->Plug();
	CSource*
		CSource::Drain() {
		ASSCHK(nGlobalInit != 0, _T("AxPipe::CGlobalInit object must exist"));

		if (!m_fIsOpen) {
			SetError(ERROR_CODE_NOTOPEN, ERROR_MSG_NOTOPEN);
			return this;
		}
		while (WorkStart(), !GetErrorCode()) {
			if (((m_pSeg = In()) != NULL) && (m_pSeg->Len() != 0)) {
				WorkSignal();
				// Always return with m_pSeg == NULL and WorkEnd() called
			}
			else {
				break;
			}
		}
		// If we have a segment, it has to be a zero-length segment we ignore.
		if (m_pSeg) {
			m_pSeg->Release();
			m_pSeg = NULL;
		}
		// At this point, WorkStart() is called, and WorkEnd() must be too.
		WorkEnd();
		return this;
	}

	/// \brief Plug this pipe, prepare for exit, cannot reopen after this.
	/// It's ok to call Plug() multiple times.
	/// \return A pointer to 'this' CSource.
	CSource*
		CSource::Plug() {
		if (!m_fExit) {
			OutPump((new CSeg)->SetType(eSegTypePlug));
		}
		return this;
	}

	/// \brief Send data to an attached CSink.
	/// \param pSeg Pointer to a CSeg containing the data to send downstream.
	void
		CSource::Out(CSeg* pSeg) {
		if (m_pSink) {
			m_pSink->OutPump(pSeg);
		}
		else {
			pSeg->Release();
		}
	}
};
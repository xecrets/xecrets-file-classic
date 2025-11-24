/*! \file
	\brief Implementation of AxPipe::CJoin, a base class for joining n-streams into one.

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
	CJoin.cpp                       Implementation of CJoin, a base class for joining n-streams into one.

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CJoin.cpp"

using AxLib::OutputDebugStringF;

namespace AxPipe {
	/// \brief Send the data to the CJoin, along with the index
	/// \param pSeg The segment of data from the input stream to pass along.
	void
		CJoin::CTSinkJoin::Out(CSeg* pSeg) {
		OutputDebugStringF(_T("CJoin::CTSinkJoin::Out()\n"));
		// Only send data if we're not empty - otherwise we may be locked up
		if (!m_fEmpty) {
			m_Sync.WorkStart();
			m_pNextSeg = pSeg;
			m_Sync.WorkSignal();
		}
		else {
			SetError(ERROR_CODE_GENERIC, _T("CJoin::CTSinkJoin::Out [Unexpected call]"));
			// If we're empty, just ignore extra data and report error.
			if (pSeg) {
				pSeg->Release();
			}
		}
	}

	/// Pass a NULL as filter conventions dictate so the CJoin reader
	/// can detect it, and not ask for more.
	/// \return false - never propagate from a sink.
	bool
		CJoin::CTSinkJoin::OutClose() {
		OutputDebugString(_T("CJoin::CTSinkJoin::OutPlug()\n"));
		Out(NULL);
		return false;
	}

	/// \brief Forward a flush request to the CJoin
	///
	/// Use filter conventions to signal the CJoin, so zero-len segment is sent.
	bool
		CJoin::CTSinkJoin::OutFlush() {
		OutputDebugString(_T("CJoin::CTSinkJoin::OutFlush()\n"));
		Out(new CSeg);
		return false;
	}

	/// Init of member variables.
	CJoin::CTSinkJoin::CTSinkJoin() {
		m_pNextSeg = NULL;
		m_fEmpty = false;
	}

	/// Check for empty condition
	/// \return true if this input stream is marked as empty.
	bool
		CJoin::CTSinkJoin::IsEmpty() {
		return m_fEmpty;
	}

	/// Called by the In() of the CJoin to get the next segment from
	/// this input stream, after returning from SinkWorkWait().
	/// \return A CSeg * to a segment.
	CSeg*
		CJoin::CTSinkJoin::GetSeg() {
		m_fEmpty = m_pNextSeg == NULL;
		return m_pNextSeg;
	}

	/// Called by the worker CJoin thread to wait for the arrival
	/// of more. CJoin expects to block waiting for more, or NULL
	/// if the end of stream is deteced.
	void
		CJoin::CTSinkJoin::SinkWorkWait() {
		m_Sync.WorkWait();
	}

	/// Called by the worker CJoin thread to signal that it's done
	/// with it's work and potentially ready for more.
	void
		CJoin::CTSinkJoin::SinkWorkEnd() {
		m_Sync.WorkEnd();
	}

	/// \brief Construct the CJoin, but Init() must also be called
	CJoin::CJoin() {
		m_nMaxStreams = 0;
		m_ppInSinks = NULL;
	}

	/// \brief Also destruct all the CTSinkJoin sink-objects.
	CJoin::~CJoin() {
		OutputDebugString(_T("CJoin::~CJoin()\n"));
		ASSCHK(m_fExit, _T("CJoin::~CJoin() with worker still active"));
		if (m_ppInSinks) {
			for (int i = 0; i < m_nMaxStreams; i++) {
				delete m_ppInSinks[i];
				m_ppInSinks[i] = NULL;
			}
			delete[] m_ppInSinks;
			m_ppInSinks = NULL;
		}
	}

	/// Handle Plug() of the stream, checking all input streams for errors too.
	void
		CJoin::OutPlug() {
		if (GetErrorCode() == ERROR_CODE_SUCCESS) {
			for (int i = 0; i < m_nMaxStreams; i++) {
				if (m_ppInSinks[i] && m_ppInSinks[i]->GetErrorCode() != ERROR_CODE_SUCCESS) {
					SetError(m_ppInSinks[i]->GetErrorCode(), m_ppInSinks[i]->GetErrorMsg());
					return;
				}
			}
		}
	}

	/// \brief Define how many streams you want here.
	/// \param nMaxStreams Specify how many streams at the max you want to join.
	CJoin*
		CJoin::Init(int nMaxStreams) {
		m_ppInSinks = new CTSinkJoin * [m_nMaxStreams = nMaxStreams];
		for (int i = 0; i < m_nMaxStreams; i++) {
			m_ppInSinks[i] = NULL;
		}
		return this;
	}

	/// Get a CSink that can be used to terminate an input stream, passing
	/// the data to the CJoin. A reference is returned, do not take the
	/// address of it and use as a pointer. This object must be destructed
	/// by the CJoin code, not the pipe it gets CPipe::Append()'ed to.
	/// \param ix The index of the input stream to get the CSink for.
	/// \return A reference to a CSink.
	CSink&
		CJoin::GetSink(int ix) {
		ASSCHK(ix < m_nMaxStreams, _T("CJoin::GetSink() [Invalid stream index]"));
		if (!m_ppInSinks[ix]) {
			return *(m_ppInSinks[ix] = new CTSinkJoin);
		}
		return *m_ppInSinks[ix];
	}

	/// \brief Wait for data from the in-stream, get it and indicate when done.
	/// \return The next segment, NULL if empty.
	CSeg*
		CJoin::StreamSeg(int ix) {
		ASSCHK(ix > m_nMaxStreams || m_ppInSinks[ix] != NULL, _T("CJoin::StreamSeg() [Invalid stream index]"));
		if (m_ppInSinks[ix]->IsEmpty()) {
			return NULL;
		}
		m_ppInSinks[ix]->SinkWorkWait();
		CSeg* pSeg = m_ppInSinks[ix]->GetSeg();
		m_ppInSinks[ix]->SinkWorkEnd();
		return pSeg;
	}

	/// \brief Set and return the current input stream index.
	/// \param ix The stream you want, it'll get reduced modulo the number of streams.
	/// \return The actual stream used guaranteed in the range 0 - (MaxIx() - 1)
	int
		CJoin::StreamIx(int ix) {
		return ix % m_nMaxStreams;
	}

	/// \brief Get the number of streams.
	/// \returns The number of streams.
	int
		CJoin::StreamNum() {
		return m_nMaxStreams;
	}

	/// \brief Tell if an indexed stream is marked as empty.
	/// \param ix The index, in the range 0 - (MaxIx() - 1)
	/// \return true if the indexed stream is marked as empty.
	bool
		CJoin::StreamEmpty(int ix) {
		return m_ppInSinks[ix]->IsEmpty();
	}
};
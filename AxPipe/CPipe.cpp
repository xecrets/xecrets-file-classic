/*! \file
	\brief Implementation of AxPipe::CPipe base class for AxPipe::CSource and other segments

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
	CPipe.cpp                       Implementation of CPipe base class for CSource and other segments

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CPipe.cpp"

namespace AxPipe {
	using AxLib::OutputDebugStringF;

	/// Destruct the chain, waiting for parts of it to finish and skipping
	/// parts that should not be auto-destructed. It will call delete for those
	/// sections that are marked for auto-destruction. It is called by the base class
	/// destructor. If you need further clean up during destruction do that in
	/// a virtual destructor. Only override this if m_pSink does not point to
	/// a CSink derived section to also include in the chain of destruction.
	void
		CPipe::DestructSink() {
		OutputDebugStringF(_T("CPipe::DestructSink() m_fAutoDeleteSink=%d, m_pSink=%p\n"), m_fAutoDeleteSink, m_pSink);
		if (m_pSink) {
			m_pSink->WaitForIdle();
			ASSCHK(m_pSink->m_fExit, _T("CPipe::DestructSink() without proper Plug()"));
			if (m_fAutoDeleteSink) {
				delete m_pSink;
			}
			else {
				m_pSink->DestructSink();
			}
			m_pSink = NULL;
		}
	}

	/// Called with m_pSeg set to whatever needs to be processed, and will call the
	/// appropriate Out function (Out(), OutOpen(), OutClose(), OutFlush() or OutSpecial())
	/// and will also handle Plug() requests by exiting.
	///
	/// Guarantees to only call Out() with valid, non-zero-length memory segments.
	void
		CPipe::Work() {
		CSeg* pSeg = m_pSeg;
		m_pSeg = NULL;

		if (DoSegWork(pSeg) && m_pSink) {
			// Propagate
			m_pSink->OutPump(pSeg);
			// If we're about to exit, wait for the the sink to exit too.
			// That way, we know that downstream has all exited before we
			// do at the return of this call.
			if (m_fExit) {
				m_pSink->WorkExitWait();
			}
		}
		else {
			pSeg->Release();
		}
	}

	/// Append the next section of the pipe, by providing a pointer to
	/// an instance. Do not call this directly, use CSource::Append().
	/// \param pSink Pointer to an instance of a CSink derived object.
	/// \param fAutoDeleteSink true if the object should be delete'd when the member upstream is delete'd.
	void
		CPipe::AppendSink(CSink* pSink, bool fAutoDeleteSink) {
		if (m_pSink) {
			m_pSink->AppendSink(pSink, fAutoDeleteSink);
		}
		else {
			m_fAutoDeleteSink = fAutoDeleteSink;
			(m_pSink = pSink)->CError::Init(this);
		}
	}
	/// Append the next section by providing a pointer to an instance. The chain of
	/// sections is scanned until it ends, and then the pointer to the segment
	/// is appended.
	/// \param pSink Pointer to an instance of a CSink derived object.
	/// \return A pointer to 'this' CPipe
	CPipe*
		CPipe::Append(CSink* pSink) {
		AppendSink(pSink, true);
		return this;
	}

	/// Append the next section by providing a reference to an instance. See the corresponding
	/// pointer version for details. Sections appended by reference are never auto-delete'd.
	/// \param sink Reference to an instance of a CSink derived object.
	/// \return A pointer to 'this' CPipe
	CPipe*
		CPipe::Append(CSink& sink) {
		AppendSink(&sink, false);
		return this;
	}

	/// Synchronize all work downstream, ensuring
	/// that there is no work in progress.
	void
		CPipe::Sync() {
		WaitForIdle();
		m_pSink->Sync();                    // Wait for the rest of the pipe too.
	}

	/// \brief Utility function, call to open the pipe downstream for output.
	void
		CPipe::Open() {
		if (m_pSink) {
			m_pSink->OutPump((new CSeg)->SetType(eSegTypeOpen));
		}
	}

	/// \brief Utility function, call typically from Out(), to send a segment downstream.
	/// \param pSeg The segment to send downstream. Do not refer to after call without call to CSeg::AddRef().
	void
		CPipe::Pump(CSeg* pSeg) {
		if (m_pSink) {
			m_pSink->OutPump(pSeg);
		}
		else {
			pSeg->Release();
		}
	}

	/// \brief Utility function, call to flush the pipe downstream.
	void
		CPipe::Flush() {
		if (m_pSink) {
			m_pSink->OutPump((new CSeg)->SetType(eSegTypeFlush));
		}
	}

	/// \brief Utility function, call to close the pipe downstream for output.
	void
		CPipe::Close() {
		if (m_pSink) {
			m_pSink->OutPump((new CSeg)->SetType(eSegTypeClose));
		}
	}

	// See the CSink comments for more details, for a non CSink object.
	// \see CSink
	CSeg*
		CPipe::GetSeg(size_t cb) {
		CSeg* pSeg = m_pSink ? m_pSink->OutGetSeg(cb) : new CSeg(cb);
		ASSPTR(pSeg);
		return pSeg;
	}

	/// Callable from user code in derived classes.
	///
	/// Called from derived classes processing code, to send an out of band
	/// signal with an opaque pointer value as the single argument downstream.
	/// This is useful when interpreted data upstream should affect the actions
	/// downstream - an example might be parsing an archive and then sending
	/// a file name downstream to a AxPipe::CSinkMemFile derived class that
	/// supports reception of the name and then opening a file under that name.
	/// \param vId A unique value identifying the signal, suggested is ClassId().
	/// \param p An opaque pointer value, interpretable by the receiver.
	void
		CPipe::Signal(void* vId, void* p) {
		if (m_pSink) {
			m_pSink->WaitForIdle();         // Ensure sync with next
			if (m_pSink->OutSignal(vId, p)) {
				m_pSink->Signal(vId, p);
			}
		}
	}

	/// Normally this is not overridden in CPipe derived classes, as
	/// it's only the CSink that can do the job. This default implementation
	/// passes the call downstream to the final CSink, and then returns the
	/// result.
	/// \return The maximum output size in bytes. -1 if unknown or unlimited.
	/// \see SizeMax()
	longlong
		CPipe::OutSizeMax() {
		return m_pSink ? m_pSink->OutSizeMax() : -1;
	}

	/// Normally not overridden in CPipe derived classes, as it's normally only
	/// a CSink that can provide an efficient alternative. This default
	/// implementation simply constructs a CSeg object of the required size.
	/// \see GetSeg() The User callable function.
	/// \return A writeable segment.
	CSeg*
		CPipe::OutGetSeg(size_t cb) {
		CSeg* pSeg = new CSeg(cb);
		ASSPTR(pSeg);
		return pSeg;
	}

	/// Override in user derived classes to receive a signal sent from upstream.
	/// This will data stream is synchronized with WaitForIdle(), so previously sent
	/// data will have reached this section, unless some intermediate section buffers.
	/// No automatic Flush() request is sent though by the framework. The CPipe default
	/// implementation does nothing but returns true to propagate it downstream.
	/// \return false to stop the signal-propagation, true to continue it.
	/// \param vId A unique value identifying the signal, suggested is ClassId().
	/// \param p An opaque pointer value, interpretable by the receiver.
	/// \see CPipe::OutSignal()
	bool
		CPipe::OutSignal(void* vId, void* p) {
		vId; //Dummy for C4100
		p; //Dummy for C4100
		return true;
	}

	/// Override in user derived classes. Called by the framework as a result of an
	/// Open() call here or upstream. Prepare for processing of a new stream, it must
	/// support being called again after a Close() call. No data may be processed by
	/// the stream without an Open() call.
	///
	/// The default implementation for a CPipe returns true, so as to have the
	/// framework propagate it downstream.
	/// \return true if the framework should propagate the Open() request downstream.
	bool
		CPipe::OutOpen() {
		return true;
	};

	/// The code should handle multiple (extra) calls to an already closed stream with
	/// no ill effects, i.e. silently ignore them. This default implementation returns
	/// true to enable propagation by the framework.
	/// \return true if the framework should propagate the Close() request downstream.
	bool
		CPipe::OutClose() {
		return true;
	};

	/// Segments may be marked as special with a non-zero value based on AxPipe::eSegType types. This are
	/// filtered out of the stream by the framework and presented here instead of to Out(). Use
	/// this in derived classes to provide in band signalling and for other custom needs.
	/// Start numbering special segments with AxPipe::eSegTypeDerived.
	///
	/// These segements may be zero-length.
	/// \return true if the framework should propagate
	/// \see AxPipe::eSegType
	bool
		CPipe::OutSpecial(CSeg* pSeg) {
		pSeg->Release();
		return true;
	}

	/// Do remember to only use default constructors in derived classes, and implement an Init()
	/// member if the class needs parameters for construction. The reason for this is the implementation
	/// of AxPipe::CThread as a template class.
	CPipe::CPipe() {
		m_pSink = NULL;
	}

	/// Destruct the sink as well, depending.
	CPipe::~CPipe() {
		DestructSink();                     // Destruct sinks, if any.
	}
};
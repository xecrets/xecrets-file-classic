/*! \file
	\brief Implementation of AxPipe::CSink base class for sinks

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
	CSink.cpp                       Implementation of CSink base class for sinks

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CSink.cpp"

namespace AxPipe {
	/// Helper function that is also called by derived classes that want slightly
	/// different Work() logic, but can leverage this common base.
	/// Checks for special AxPipe::eSegType types, and calls the appropriate OutOpen(),
	/// OutClose(), OutFlush() and Out() functions depending on the case.
	/// Only in the case of Out() does the actual data segment get passed on. Any custom
	/// AxPipe::eSegType segment types gets passed as normal segments to Out().
	/// Ensures that the pipe is Open() at this stage before sending data etc.
	/// \return true if the caller should propagate the segment. The pSeg is never CSeg::Release()'d here. Caller must.
	bool
		CSink::DoSegWork(CSeg* pSeg) {
		bool fPropagate;                    // true if we propagate in band signals

		switch (pSeg->Type()) {
		case eSegTypeOpen:
			fPropagate = OutOpen();
			// Can't set this false before we've closed properly
			m_fIsOpen = true;
			return fPropagate;
			break;

		case eSegTypeFlush:
			return OutFlush();
			break;

		case eSegTypeClose:
			if (m_fIsOpen) {
				fPropagate = OutClose();
				// Can't set this false before we've closed properly
				m_fIsOpen = false;
			}
			else {
				// If we're not open doesn't make sense to propagate close
				fPropagate = false;
			}
			return fPropagate;
			break;

		case eSegTypePlug:
			// Set the exit so we can end if it's a thread etc.
			OutPlug();                      // Call this class's Plug-function
			fPropagate = m_fExit = true;
			return fPropagate;
			break;

		case 0:
			if (!m_fIsOpen) {
				SetError(ERROR_CODE_NOTOPEN, ERROR_MSG_NOTOPEN);
				break;
			}
			// Ignore zero-length segments.
			if (pSeg->Len()) {
				// non-zero length data segment.
				// Out() will not be called with anything else. CFilter derived classes have slightly
				// different rules.
				Out(pSeg->AddRef());
			}
			break;
		default:
			// It's an special/unknown segment type, call the handler (even with zero-length)
			// Note that we auto propagate special segments, even if they are semantially similar
			// to normal data segments.
			// CSeg::AddRef() it since the OutSpecial() handler is expected to CSeg::Release() it - as will the caller of DoSegWork()
			return OutSpecial(pSeg->AddRef());
			break;
		}
		return false;
	}

	/// Called with CSink::m_pSeg set to whatever needs to be processed.
	/// Work guarantees to never call Out() with anything but a valid, non-zero-length
	/// data segment. Other cases are handled by OutOpen(), OutClose() and OutFlush().
	/// A Plug() request causes nothing to be sent to Out().
	void
		CSink::Work() {
		CSeg* pSeg = m_pSeg;
		m_pSeg = NULL;

		(void)DoSegWork(pSeg);
		// DoSegWork() never releases, so we must.
		pSeg->Release();
	}

	/// Unless we're already exited, end processing and wait for it to reach
	/// idle state. Should not be called from Work() or Out(). Finally, we
	/// wait for the worker thread, if any, to actually exit, thus assuring
	/// that when Plug() returns, it is safe to call the destructor.
	/// The purpose of Plug is to finalize all processing and to ensure that
	/// any errors are found and reported. Final error checking for processing should
	/// thus not be done before Plug() is called. After Plug() is called, the
	/// only thing that should be done with the object and the pipe line is
	/// to destruct it.
	void
		CSink::OutPlug() {
		AxLib::OutputDebugStringF(_T("CSink::OutPlug() m_fExit=%d\n"), m_fExit);
	}

	/// Allocate a new segment, possibly from the next section of the pipe.
	///
	/// Callable from user code in derived classes.
	///
	/// Call this to get a segment if you suspect the next in line is a sink that
	/// might provide an efficient segment, such as for a memory mapped file.
	/// \return A writeable CSeg of the requested size, or NULL on error.
	CSeg*
		CSink::GetSeg(size_t cb) {
		return new CSeg(cb);
	}

	/// \brief Send Out-of-band signal. Callable from user code in derived classes.
	///
	/// Does nothing, this is a CSink.
	/// \see CPipe::Signal()
	void
		CSink::Signal(void* vId, void* p) {
		vId; //Dummy for C4100
		p; //Dummy for C4100
	}

	/// Callable from user code in derived classes.
	///
	/// \return The maximum output size in bytes. -1 if unknown or unlimited.
	/// \see OutSizeMax() The corresponding overrideable
	longlong
		CSink::SizeMax() {
		return OutSizeMax();
	}

	/// Do not call from user code, only from derived framework classes.
	/// The normal usage is to have the previous section up the line
	/// call this via it's CPipe::m_pSink pointer, the roundabout way is
	/// to enable seamless threading.
	/// Is frequently called from other library-internal classes, therefore public
	/// \param pSeg The segment to send off to Work(). Don't use it afterwards unless you've CSeg::AddRef()'d it.
	void
		CSink::OutPump(CSeg* pSeg) {
		WorkStart();
		m_pSeg = pSeg;
		WorkSignal();
	}

	/// Override this in user derived classes to return the maximum size
	/// of the sink, or -1 for expandable. The default CSink implementation
	/// always returns -1.
	/// \return The maximum output size in bytes. -1 if unknown or unlimited.
	/// \see SizeMax()
	longlong
		CSink::OutSizeMax() {
		return -1;
	}

	/// Override in user derived classes to provide an efficient memory segment
	/// output from a CSink, especially for memory mapped files.
	/// \see GetSeg() The User callable function.
	/// \return A writeable segment.
	CSeg*
		CSink::OutGetSeg(size_t cb) {
		CSeg* pSeg = new CSeg(cb);
		ASSPTR(pSeg);
		return pSeg;
	}

	/// Override in user derived classes to receive a out-of band signal sent from upstream.
	/// This will be called synchronized with the data stream, so previously sent
	/// data will have reached this section, unless some intermediate section buffers.
	/// No automatic Flush() request is sent though. This CSink default implementation
	/// does nothing and returns false to stop propagation, since it's CSink.
	/// \return false to stop the signal-propagation, true to continue it.
	/// \param vId A unique value identifying the signal, suggested is ClassId().
	/// \param p An opaque pointer value, interpretable by the receiver.
	/// \see CPipe::OutSignal()
	/// \sse CPipe::OutSpecial()
	bool
		CSink::OutSignal(void* vId, void* p) {
		vId; //Dummy for C4100
		p; //Dummy for C4100
		return false;
	}

	/// Override in user derived classes. Called by the framework as a result of an
	/// Open() call here or upstream. Prepare for processing of a new stream, it must
	/// support being called again after a Close() call. No data may be processed by
	/// the stream without an Open() call.
	///
	/// The default implementation for a CSink returns false, as it does not make
	/// sense to propagate downstream from a CSink()
	/// \return true if the framework should propagate the Open() request downstream.
	bool
		CSink::OutOpen() {
		return false;
	};

	/// You are not required to honor the request.
	/// \return true if the framework should propagate the Flush() request downstream.
	bool
		CSink::OutFlush() {
		return false;
	};

	/// The code should handle multiple (extra) calls to an already closed stream with
	/// no ill effects, i.e. silently ignore them. This default implementation returns
	/// false to stop propagation, since it's a CSink.
	/// \return true if the framework should propagate the Close() request downstream.
	bool
		CSink::OutClose() {
		return false;
	};
	/// Segments may be marked as special with a non-zero value based on AxPipe::eSegType types. These are
	/// filtered out of the stream by the framework and presented here instead of to Out(). Use
	/// this in derived classes to provide in band signalling and for other custom needs. Start
	/// numbering from AxPipe::eSegTypeDerived.
	///
	/// The default implementation here just calls CSeg::Release() on the provided CSeg .
	///
	/// These segements may be zero-length.
	/// \return false, since we're at the end of the line. No more propagation.
	/// \see AxPipe::eSegType
	bool
		CSink::OutSpecial(CSeg* pSeg) {
		pSeg->Release();
		return false;
	}

	/// Initialize member variables.
	CSink::CSink() {
		m_pSeg = NULL;
		m_fIsOpen = false;
	}

	/// Plug the pipe, destroy the sink and release remaining m_pSeg if any
	CSink::~CSink() {
		OutputDebugStringF(_T("CSink::~CSink() Initating... this=%p\n"), this);
		ASSCHK(m_fExit, _T("CSink::~CSink() called without Plug()"));
		if (CSeg::IsSeg(m_pSeg)) m_pSeg->Release();
		OutputDebugStringF(_T("CSink::~CSink() ...Done. this=%p\n"), this);
	}

	/// You can't append a CSink to a CSink, so this implements code to catch
	/// that error.
	void
		CSink::AppendSink(CSink* pSink, bool fAutoDelete) {
		pSink; //Dummy for C4100
		fAutoDelete; //Dummy for C4100
		SetError(ERROR_CODE_GENERIC, _T("Attempt to append to a sink"));
	}

	/// Synchronize all work downstream, ensuring
	/// that there is no work in progress.
	void
		CSink::Sync() {
		WaitForIdle();
		// Do no more, this is a CSink - It's the end of the line.
	}

	/// Called by the virtual destructor, the default implementation for CSink
	/// does nothing. The purpose of DestructSink() is to ensure that the
	/// whole chain gets destructed, also depending on if they should be
	/// auto deleted. It should be called by the destructor before it
	/// does the remaining destructing.
	void
		CSink::DestructSink() {
		OutputDebugString(_T("CSink::DestructSink()\n"));
	}
};
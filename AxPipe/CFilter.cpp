/*! \file
	\brief Implementation of AxPipe::CFilter, pull-style filters of different kinds

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

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	CFilter.cpp                     Implementation of CFilter, pull-style filters of different kinds

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CFilter.cpp"

namespace AxPipe {
	/// \brief Helper static member function to send as StartProc to the CCoContext m_ctxFilter.
	///
	/// It's only function is to get us 'back into the class', by calling CoStartFilter().
	/// \param pvThis A pointer to 'this' CFilter.
	void
		CFilter::CoFilter(void* pvThis) {
		((CFilter*)pvThis)->CoStartFilter(pvThis);
#ifdef _DEBUG
		// Should never get here!
		ASSERR(_T("CFilter::CoFilter unexpected fiber exit"));
#endif
	}

	/// \brief Initialize member variables.
	CFilter::CFilter() {
		m_ctxFilter.Init(this, CoFilter, this);
		m_ctxWork.Init(this, NULL, NULL);   // The Work context starts as the 'current'
		m_fFirstWork = true;                // Ensure that we know when Work() is called first time.
	}

	CFilter::~CFilter() {
		m_ctxFilter.Stop();
	}

	/// \brief Overriden Out() to handle switching to Filter co-routine context.
	///
	/// A CFilter derived Out() may be called with zero-length and NULL pSeg from OutClose() and
	/// OutFlush(), as this is how those conditions are signalled to the InFilter() via Read().
	/// \param pSeg The segment to send to the filter.
	void
		CFilter::Out(CSeg* pSeg) {
		if (!m_fIsOpen) {
			SetError(ERROR_CODE_NOTOPEN, ERROR_MSG_NOTOPEN);
			return;
		}

		m_pSeg = pSeg;
		// Switch to Read() and InFilter()
		//OutputDebugString(_T("CFilter::Out(CSeg *pSeg) m_ctxFilter.Go()\n"));
		m_ctxFilter.Go();
	}

	/// \brief Prepare for processing.
	///
	/// Filters by default do nothing on Open() request, this is called
	/// by Work() in the worker thread upon reception of the open
	/// in band signal.
	///
	/// If overriden in derived classes, CFilter::OutOpen() must also be
	/// called, to ensure proper co-routine context initialization. Normally
	/// this will not be overridden for CFilter derived classes.
	///
	/// \return true to cause propagation of Open() - the default here is false.
	bool
		CFilter::OutOpen() {
		OutputDebugString(_T("CFilter::OutOpen()\n"));
		if (m_fFirstWork) {
			// If first time, ensure we are executing in Work coroutine context now
			OutputDebugString(_T("CFilter::OutOpen() m_ctxWork.Go()\n"));
			m_ctxWork.Go();                 // This only initializes the context...
			m_fFirstWork = false;           // ...we get here immediately
		}
		// Default for filters is to not propagate
		return false;
	}

	/// \brief Send a NULL segment close signal to InFilter() and Read().
	///
	/// If overriden in derived classes, CFilter::OutClose() must also be
	/// called, to ensure signalling to InFilter() / Read() . Normally
	/// this will not be overridden for CFilter derived classes.
	/// \return true to cause propagation of Close() - the default here is false.
	bool
		CFilter::OutClose() {
		Out(NULL);
		// Default for filters is to not propagate
		return false;
	}

	/// \brief Send flush-request as a zero-length segment to Read()
	/// \return true to cause propagation of Flus() - the default here is true.
	bool
		CFilter::OutFlush() {
		Out(new CSeg);
		return true;
	}

	/// \brief Send the m_pSeg segment to the Filter
	///
	/// This override of the default adds the stopping of the filter context
	/// upon reception of a plug signal.
	void
		CFilter::Work() {
		CPipe::Work();
	}

	/// \brief The start in-class of the filter co-routine context.
	/// We get here when we have the first data segment ready for the InFilter()
	/// and we're opened by the previous.
	/// \param pvThis A pointer to 'this' CFilter (not really necessary).
	void
		CFilter::CoStartFilter(void* pvThis) {
		pvThis; // Dummy for C4100
		// The filter may be called multiple times. It should exit when receiving
		// a eSegTypeClose segment, ready to be called again when more arrives.
		for (;;) {
			OutputDebugStringF(_T("CFilter::CoStartFilter(void *pvThis) InFilter(), this=%p\n"), this);
			InFilter();                     // Shold return when eof/empty is signalled.

			// Drive the sender until we either get a valid data segment, or we're killed
			do {
				OutputDebugStringF(_T("CFilter::CoStartFilter waiting for data, this=%p\n"), this);
				m_ctxWork.Go();
			} while (m_pSeg == NULL || m_pSeg->Len() == 0);
			OutputDebugStringF(_T("CFilter::CoStartFilter found data, this=%p\n"), this);
		}
		// Never get here!
	}

	/// \brief Get a segment, call from InFilter().
	///
	/// Get a valid, zero-length or NULL segment for data, flush and
	/// close respectively.
	/// \return A memory segment, or zero-length or NULL (not an error).
	CSeg*
		CFilter::Read() {
		// We may already have a segment waiting, at first call.
		if (!m_pSeg) {
			m_ctxWork.Go();
		}
		// m_pSeg can be valid, zero-length or NULL here. Nothing else.
		CSeg* pSeg = m_pSeg;
		m_pSeg = NULL;
		return pSeg;
	}
	/// \brief Helper routine to get next segment.
	///
	/// m_pSeg can only be valid, zero-length or NULL here.
	/// If we already have a valid segment in m_pSeg, we don't
	/// get a new one.
	/// \return true if we return with a segment ready to use in m_pSeg.
	bool
		CFilterByte::GetNextSeg() {
		// Release if empty.
		if (m_pSeg && !m_pSeg->Len()) {
			m_pSeg->Release();
			m_pSeg = NULL;
		}
		if (!m_pSeg) {
			m_ctxWork.Go();
		}
		return m_pSeg != NULL;              // Success as long as we get a segment, but it might be zero-len
	}
	/// \brief Read a byte from the stream.
	/// \return A byte as an int, or -1 on eos or error
	int
		CFilterByte::ReadByte() {
		do {
			if (!GetNextSeg()) {
				return -1;
			}
		} while (!m_pSeg->Len());       // Ignore flush requests, just wait for data.

		// Now we now we have at least one byte.
		unsigned char c = *m_pSeg->PtrRd();
		m_pSeg->Drop(1);
		return c;
	}

	/// \brief Errror catcher, can't call Read() from CFilterByte derived.
	CSeg*
		CFilterByte::Read() {
		SetError(ERROR_CODE_GENERIC, ERROR_MSG_GENERIC, _T("Attempt to call CFilterByte::Read()"));
		return NULL;
	}

	/// \brief Skip bytes in stream.
	/// \param cb Number of bytes to skip
	/// \return Number of bytes not skipped because stream ended prematurely.
	size_t
		CFilterByte::Skip(size_t cb) {
		while (cb) {
			if (!GetNextSeg()) {
				break;
			}
			size_t cbChunk = m_pSeg->Len();
			if (cbChunk > cb) {
				cbChunk = cb;
			}
			m_pSeg->Drop(cbChunk);
			cb -= cbChunk;
		}
		return cb;
	}

	/// \brief Attempt to get a segment of a requested size.
	///
	/// Always get the amount requested if possible. Return less than requested if
	/// EOS is detected. Can return NULL. Cannot return zero-length
	/// For this type of filter, honoring and handling flush-requests
	/// do not really make sense. Use a regular CFilter or CPipe if you need do do
	/// that. Asking for zero bytes means that we'll take what we get, right now we
	/// don't care about how much we get.
	/// \param cb The number of bytes we want in the returned segment.
	/// \return A segment with the request number of bytes, or less if eos, or NULL if no data at all.
	CSeg*
		CFilterBlock::ReadBlock(size_t cb) {
		// Zero means take what we get
		if (!cb) {
			while (GetNextSeg()) {
				if (m_pSeg->Len()) {
					CSeg* pSeg = m_pSeg;
					m_pSeg = NULL;
					return pSeg;
				}
				m_pSeg->Release();
				m_pSeg = NULL;
			}
			return NULL;                    // No data - this is shown with NULL
		}
		// If no buffered data - we must get more in any case, so let's do it.
		if (!GetNextSeg()) {
			return NULL;                    // No data to get.
		}
		// This is a slight optimization to try to keep chunks in the original
		// segment as much as possible.
		// If the buffer contains the proper number of bytes already, clone it,
		// drop the bytes off the original, and set the length of the copy
		// returned.
		if (m_pSeg->Len() >= cb) {
			CSeg* pSeg = m_pSeg->Clone();
			m_pSeg->Drop(cb);
			pSeg->Len(cb);
			return pSeg;
		}

		// Now we know we must merge two or more buffers. Let's allocate a segment to return.
		CSeg* pSeg = new CSeg(cb);
		if (!pSeg) {
			SetError(ERROR_CODE_GENERIC, ERROR_MSG_GENERIC, _T("Out of memory"));
			return NULL;
		}

		size_t cbSeg;
		pSeg->Len(cbSeg = 0);           // Set the length of valid data in the segment to zero.
		// We also know at this point that we have valid data in the buffer.
		for (;;) {
			size_t cbChunk = m_pSeg->Len();
			if (cbChunk > cb - cbSeg) {
				cbChunk = cb - cbSeg;
			}
			memcpy(&pSeg->PtrWr()[cbSeg], m_pSeg->PtrRd(), cbChunk);
			m_pSeg->Drop(cbChunk);
			pSeg->Len(cbSeg += cbChunk);// Update the length of valid data in the segment.

			// If we've gotten all we need...
			if (cbSeg == cb) {
				return pSeg;
			}

			if (!GetNextSeg()) {
				return pSeg;        // Return what data we have.
			}
		}
		// Can't get here!
	}
};
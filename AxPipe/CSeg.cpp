/*! \file
	\brief Implementation of AxPipe::CSeg reference counted memory objects

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
	CSeg.cpp                        Implementation of CSeg reference counted memory objects

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-11-23              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CSeg.cpp"

namespace AxPipe {
	/// Constructor helper, init's a CSeg appropriately
	void
		CSeg::Init(size_t cbBuf, void* pvBuf, bool fReadOnly, int iType) {
		InitializeCriticalSection(&m_CritSect);
		m_iType = iType;
		m_pMom = NULL;
		m_fReadOnly = fReadOnly;
		m_cbLen = m_cbBuf = cbBuf;
		if (m_cbLen) {
			m_fOwnPtr = (pvBuf == NULL);
			if (!m_fOwnPtr) {
				m_pvBuf = static_cast<unsigned char*>(pvBuf);
			}
			else {
				m_pvBuf = new unsigned char[m_cbBuf];
			}
		}
		else {
			m_fOwnPtr = false;
			m_pvBuf = NULL;
		}
		m_cbOff = 0;
		m_iRefCnt = 1;
	}

	/// Copy by assignment makes a dependent copy of the original
	/// section. It inherits the buffer, but is considered a child
	/// of the original.
	CSeg&
		CSeg::operator=(CSeg& rhs) {
		EnterCriticalSection(&m_CritSect);

		// Here we should have some check for assignment to non-empty lhs
		// and clear that. We don't implement that right now.
		m_pMom = &rhs;
		m_pvBuf = rhs.m_pvBuf;
		m_cbBuf = rhs.m_cbBuf;
		m_cbLen = rhs.m_cbLen;
		m_cbOff = rhs.m_cbOff;
		m_fReadOnly = rhs.m_fReadOnly;
		m_fOwnPtr = false;                  // A copy can never own the buffer.

		LeaveCriticalSection(&m_CritSect);

		rhs.AddRef();
		return *this;
	}

	/// \param cbBuf The size of the buffer provided. If provided, please provide a non-NULL buffer.
	/// \param pvBuf Pointer to a buffer with cbBuf bytes. This buffer will be referred to by the CSeg.
	/// \param fReadOnly Set to true if the provided buffer is read-only.
	CSeg::CSeg(size_t cbBuf, void* pvBuf, bool fReadOnly) {
		Init(cbBuf, pvBuf, fReadOnly, 0);
	}

	/// \param cbBuf The size of the buffer provided. Please provide a non-NULL buffer.
	/// \param pvBuf Pointer to a buffer with cbBuf bytes of read-only data.
	CSeg::CSeg(size_t cbBuf, const void* pvBuf) {
		Init(cbBuf, (void*)pvBuf, true, 0);
	}

	/// \param pvBuf Pointer to a buffer with cbLen bytes of valid data to copy
	/// \param cbLen Number of valid bytes data in the buffer to copy
	/// \param cbGrowBuf Number of bytes to increase the new buffer to
	CSeg::CSeg(const void* pvBuf, size_t cbLen, size_t cbGrowBuf) {
		Init(cbLen + cbGrowBuf, NULL, false, 0);

		// Decrease length to the valid part.
		m_cbLen = cbLen;

		// Initialize the allocated buffer with the data provided
		CopyMemory(m_pvBuf, pvBuf, cbLen);
	}

	/// Never allocate a CSeg as auto or static.
	///
	/// Note that the destructor does nothing - Release() does all the work, including delete this;
	/// Here we don't need a critical section, as the destructor is only called from
	/// within the class, and by definition only by one thread.
	/// With the exception of catastrophic internal error where the destructor
	/// is called prematurely, this is by definition thread-safe in the sense
	/// that only one thread should be active and attempt to destruct it.
	CSeg::~CSeg() {
		if (m_iRefCnt) {
			MessageBox(NULL, _T("CSeg::~CSeg() bad call or double-delete"), _T("http://www.axondata.se"), MB_OK);
		}
		else {
			if (m_pMom) {
				m_pMom->Release();
			}
			else if (m_pvBuf && m_fOwnPtr) {
				delete[] m_pvBuf;
				m_pvBuf = NULL;
			}
		}
		DeleteCriticalSection(&m_CritSect);
	}

	/// This is the raw buffer pointer, unaffected by offsets or anything else,
	/// and it's also not const or anything, regardless of read-only status.
	/// \return The really raw buffer pointer. Use with caution.
	unsigned char*
		CSeg::Ptr() {
		// m_pvBuf is only initialized in the constructor, so this is thread-safe
		return m_pvBuf;
	}

	/// \return const pointer to valid data, including offset.
	const unsigned char*
		CSeg::PtrRd() {
		const unsigned char* r;
		EnterCriticalSection(&m_CritSect); {
			r = &m_pvBuf[m_cbOff];
		} LeaveCriticalSection(&m_CritSect);
		return r;
	}

	/// If you really need to get write-access to the buffer, use CSeg::Writeable().
	/// \return Pointer to valid writeable data, unless it's read-only. Then return NULL.
	unsigned char*
		CSeg::PtrWr() {
		// m_fReadOnly is only initialized in the constructor, thus thread-safe
		return m_fReadOnly ? NULL : (unsigned char*)(PtrRd());
	}

	/// You may not refer to this CSeg* again, as it will have been Release() 'd.
	/// It only returns the data known to be valid in the buffer, not the raw buffer.
	/// Do check the length with Len() first, to find how much data there is.
	/// \return A buffer free to use, no longer associated with this CSeg. Must Allocator::FreeX
	unsigned char*
		CSeg::PtrRelease() {
		// Return a buffer that is free to use.
		unsigned char* p;
		EnterCriticalSection(&m_CritSect); {
			if (!m_fOwnPtr || (m_iRefCnt > 1) || m_pMom || m_cbOff) {
				p = new unsigned char[Len()];
				if (p) {
					memcpy(p, PtrRd(), Len());
				}
			}
			else {
				p = &m_pvBuf[m_cbOff];
				m_pvBuf = NULL;
			}
		} LeaveCriticalSection(&m_CritSect);

		Release();
		return p;
	}

	/// This is not necessarily the same as the Len() of the buffer,
	/// nor is it necessarily the same as the size of the raw buffer.
	/// \return Bytes in buffer from offset to end of raw buffer.
	size_t
		CSeg::Size(void) {
		size_t s;
		EnterCriticalSection(&m_CritSect); {
			s = m_cbBuf - m_cbOff;
		} LeaveCriticalSection(&m_CritSect);
		return s;
	}

	///
	/// \return The number of bytes of valid data.
	size_t
		CSeg::Len(void) {
		size_t l;
		EnterCriticalSection(&m_CritSect); {
			l = m_cbLen - m_cbOff;
		} LeaveCriticalSection(&m_CritSect);
		return l;
	}

	///
	/// \return A pointer to this.
	CSeg*
		CSeg::Len(size_t cbLen) {
		EnterCriticalSection(&m_CritSect); {
			m_cbLen = cbLen + m_cbOff;
		} LeaveCriticalSection(&m_CritSect);
		return this;
	}

	/// Make a writeable CSeg of ourselves. If we already are
	/// writeable, just return 'this' and increment the ref count.
	///
	/// If we're readonly, make a new section and copy the valid
	/// data we have there.
	/// \return Pointer to a writeable CSeg.
	CSeg*
		CSeg::Writeable() {
		if (m_fReadOnly) {
			CSeg* pWriteable;
			EnterCriticalSection(&m_CritSect); {
				pWriteable = new CSeg(Len());
				memcpy(pWriteable->PtrWr(), PtrRd(), Len());
			} LeaveCriticalSection(&m_CritSect);
			return pWriteable;
		}
		else {
			return AddRef();
		}
	}

	/// Don't Drop() more than Len() bytes.
	/// \param cbOff The number of bytes to drop at the start.
	/// \return A pointer to this.
	CSeg*
		CSeg::Drop(size_t cbOff) {
		EnterCriticalSection(&m_CritSect); {
			m_cbOff += cbOff;
		} LeaveCriticalSection(&m_CritSect);
		return this;
	}

	/// \brief Increment the reference count of this object.
	/// \return A pointer to this.
	CSeg*
		CSeg::AddRef() {
		// II makes it thread-safe
		InterlockedIncrement(&m_iRefCnt);
		return this;
	}

	/// Decrement the reference counter, and self destruct if
	/// it reaches zero.
	///
	/// If we're a child of another base section, decrement
	/// that reference count if our reference reaches zero.
	///
	/// Never reference a CSeg * after calling Release().
	/// \return Zero if this was the last reference.
	int
		CSeg::Release() {
		LONG i = InterlockedDecrement(&m_iRefCnt);
		if (i == 0) {
			// This is why you must *never* reference a CSeg* after calling Release()
			// This is also why you must *never* delete  CSeg manually, nor allocate
			// one as auto or static.
			delete this;
		}
		return i;
	}

	/// A CSeg may have an arbitrary int associated with it. The default
	/// is zero, but it may be set to any value by other classes, and
	/// it may be used for any purpose. AxPipe defines some reserved values
	/// in AxPipe::eSegType.
	/// \see eSegType
	/// \return The type as an int.
	int
		CSeg::Type() {
		// m_iType should only be set in construction, thus thread-safe
		return m_iType;
	}

	/// \see Type()
	/// This is not thread-safe strictly speaking - so must only be called
	/// when there is a single reference.
	/// \return A pointer to 'this' CSeg
	CSeg*
		CSeg::SetType(int iType) {
		m_iType = iType;
		return this;
	}

	/// Checks for NULL pointer and non-default Type().
	/// \return true if the pointer is a valid standard segment pointer.
	bool
		CSeg::IsSeg(CSeg* pSeg) {
		return (pSeg != NULL && !pSeg->Type());
	}

	/// The result is a child copy of the original - they share the buffer, but
	/// have individual offsets and lengths.
	/// \return A pointer to this.
	CSeg*
		CSeg::Clone() {
		// The operator= handles thread-issues
		return &(*new CSeg = *this);
	}

	/// \brief Run-time type identifcation.
	///
	/// We're not using the built in RTTI because we sometimes want to be able
	/// to forego most of the run time library, as well as exceptions and RTTI.
	///
	/// The point here is to create a guaranteed unique value that is the same
	/// for all instances of a class, while not requiring any inits outside
	/// of the class declaration, and also to 'fool' optimizing compilers, so
	/// that they cannot perform global optimization and figure out that it can
	/// fold identical functions into one. It happened in a previous version...
	/// That's why we include the static int, it can't be optimized away, at least
	/// not easily.
	/// You need to override ClassId() and RTClassId() in all derived clases you
	/// want to distinguish, this is
	/// most easily done by simply copying and pasting exactly these definitions.
	/// There is also the Run-Time version, accessible through a pointer to a
	/// polymorphic base-class for example, RTClassId().
	void*
		CSeg::ClassId() {
		static int i;
		return &i;
	}

	/// \brief Run-Time version of our type identification.
	/// \see ClassId()
	void*
		CSeg::RTClassId() {
		return ClassId();
	}
};
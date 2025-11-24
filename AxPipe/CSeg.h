#pragma once
#ifndef AXPIPE_CSEG_H
#define AXPIPE_CSEG_H
/*! \file CSeg.h
	\brief Reference counted memory buffers AxPipe::CSeg

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

	Why is this framework released as GPL and not LGPL?
	See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	CSeg.h                          Reference counted memory buffers

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-05              Initial
\endverbatim
*/
#include "AxPipe.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CSeg.h"

namespace AxPipe {
	/// \brief Reference counted memory buffer objects.
	///
	/// Objects of this kind *must* not be instantiated by any other
	/// means than 'new'. No arrays, no static, and no automatic. When
	/// the reference count falls to zero, they are deleted automagically.
	///
	/// You must *never* reference a pointer after a call to Release().
	/// You must *never* 'delete' a pointer manually. Let Release() do it.
	///
	/// The default is that these objects are read-write. You can determine
	/// this by attempting to get a PtrWr(). If you get NULL, you must
	/// copy. You set them read-only by specifying this in the constructor.
	///
	/// A CSeg consists of a buffer, referenced by a pointer. The buffer may be
	/// owned by the CSeg object, or not. If it is, it'll be deleted when the last
	/// reference to the object is Released() 'd.
	///
	/// Not all of the buffer may consist valid data, the start in the buffer may
	/// be adjusted by an internally maintained offset, and the length of valid data
	/// by an internally maintained length of valid data starting from the offset.
	///
	/// General rule of usage:
	/// Always allocate with new - never create static or automatic CSeg objects, only through CAutoSeg
	/// When you pass a copy elsewhere, especially if it is potentially a different thread, call AddRef().
	/// When you're done with your instance, call Release().
	/// Never perform a 'delete' on a CSeg *.
	/// Never reference a CSeg after passing it anywhere without a prior AddRef() call!
	///
	/// CSeg's are thread safe in two ways. The reference count, m_iRefCnt, is only read and written
	/// using the InterlockedIncrement()/InterlockedDecrement() API which are inherently thread safe.
	/// In other functions, references to values that may be written at other times than object
	/// construction and initialization, a critical section is used as necessary to ensure thread safeness.
	class CSeg {
	private:
		volatile LONG m_iRefCnt;                ///< Reference count. volatile due to InterlockedXXX req's
		CRITICAL_SECTION m_CritSect;            ///< This object may be shared among threads, thus needs this.

		unsigned char* m_pvBuf;                 ///< The raw data buffer pointer. Never changed once set.
		size_t m_cbBuf;                         ///< The raw data buffer size - not the same as how much valid data.
		CSeg* m_pMom;                           ///< Owning object, if this is a child.
		bool m_fOwnPtr;                         ///< True if this CSeg owns and manages the data buffer.
		bool m_fReadOnly;                       ///< True if this is a read-only object.
		int m_iType;                            ///< Opaque type indicator, free to use. Do note usage in AxPipe::eSegType

		size_t m_cbOff;                         ///< Current offset from start of raw buffer to valid data.
		size_t m_cbLen;                         ///< Current number of valid bytes of raw data, starting at CSeg::m_cbOff

		/// Constructor helper, init's a CSeg appropriately
		void Init(size_t cbBuf, void* pvBuf, bool fReadOnly, int iType);

		/// \brief Make a dependent copy of the original.
		CSeg& operator=(CSeg& rhs);

	public:
		/// \brief Default, and full-function, ctor for non-owned (not deleted on destruction).
		CSeg(size_t cbBuf = 0, void* pvBuf = NULL, bool fReadOnly = false);

		/// \brief For constant data, and thus set ReadOnly true; Non-owned data (not deleted).
		CSeg(size_t cbBuf, const void* pvBuf);

		/// \brief Construct an owned buffer with a copy of provided data, possibly also in a larger buffer.
		CSeg(const void* pvBuf, size_t cbLen, size_t cbGrowBuf = 0);

		/// \brief Delete buffer if owned, Release() parent, if child and delete critical section.
		virtual ~CSeg();

		unsigned char* Ptr();                   ///< Get the raw buffer pointer.
		const unsigned char* PtrRd();           ///< Get a read-only pointer to the valid data in the buffer, using m_cbOff.
		unsigned char* PtrWr();                 ///< Get a writeable pointer to the valid data.
		unsigned char* PtrRelease();            ///< Get an independent free buffer with valid data and also Release().
		size_t Size(void);                      ///< Get the number of useable bytes in the buffer.
		size_t Len(void);                       ///< Get the length of valid data in bytes in the segment.
		CSeg* Len(size_t cbLen);                ///< Set the length of valid data in bytes in the segment.
		CSeg* Writeable();                      ///< Get a definitely writeable CSeg *, possibly a copy.
		CSeg* Drop(size_t cbOff);               ///< Drop cbOff bytes at the start of the buffer.
		CSeg* AddRef();                         ///< Increment the reference count of this object.
		int Release();                          ///< Decrement the reference count of this object.
		int Type();                             ///< Get the type, an opaque user-defined non-zero integer.
		CSeg* SetType(int iType);               ///< Set the type, an opaque user-defined non-zero integer.
		static bool IsSeg(CSeg* pSeg);          ///< Check if a segment pointer is valid reference to standard data.
		CSeg* Clone();                          ///< Make a clone of ourself
		static void* ClassId();                 ///< Run-time type identifcation.
		virtual void* RTClassId();              ///< Run-Time version of our type identification.
	};

	/// \brief std::auto_ptr like functionality with CSeg pointers.
	///
	/// If you really want auto_ptr-functionality with our reference counted CSeg's, use
	/// this class like you would auto_ptr, with some limitations. You can't use auto_ptr,
	/// as the proper way to dispose of a CSeg * is not to delete it, but to CSeg::Release() it.
	/// \param T A CSeg-based class.
	template<class T> class Auto_Seg {
	private:
		T* m_p;                                 ///< The pointer to the CSeg-derived object.

		/// \brief Call CSeg::Release() if the pointer is valid.
		inline void Release() {
			if (m_p) {
				m_p->Release();
			}
		}
	public:
		/// \brief Construct with a given CSeg-derived pointer, or NULL if none given.
		inline Auto_Seg(T* p = NULL) {
			m_p = p;
		}

		/// \brief Basically just CSeg::Release()
		inline ~Auto_Seg() {
			Release();
		}

		/// \brief Assign a new CSeg-derived pointer, CSeg::Release() the current, if any.
		inline Auto_Seg<T>& operator=(T* p) {
			Release();
			m_p = p;
			return *this;
		}

		/// \brief Assign a pointer to a CSeg object, CSeg::AddRef() the source first.
		inline Auto_Seg<T>& operator=(T& rhs) {
			rhs.AddRef();
			return *this = &rhs;
		}

		/// \brief Assign a Auto_Seg-derived reference.
		inline Auto_Seg<T>& operator=(Auto_Seg<T>& rhs) {
			if ((T*)rhs) {
				rhs->AddRef();
			}
			return *this = rhs.m_p;
		}

		/// \brief Reference the CSeg-derived pointer as a pointer.
		inline T* operator ->() {
			return m_p;
		}

		/// \brief Get the referenced CSeg-derived pointer.
		inline T* get() {
			return m_p;
		}

		/// \brief Get the reference CSeg-derived pointer, and then clear the reference here.
		inline T* release() {
			T* p = m_p;
			m_p = NULL;
			return p;
		}
	};
	/// \brief Use pretty much as you would auto_ptr<CSeg> if you could have done that, which you can't.
	typedef Auto_Seg<CSeg> CAutoSeg;
}; // namespace AxPipe
#endif AXPIPE_CERROR_H

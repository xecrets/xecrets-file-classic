#pragma once
#ifndef AXPIPE_H
#define AXPIPE_H
/*! \file
	\brief Main class declarations, AxPipe::CSource, AxPipe::CPipe, AxPipe::CFilter, AxPipe::CSink, AxPipe::CSplit, AxPipe::CJoin

	@(#) $Id$
*/
/*! \page License AxPipe - Multi-Threaded Binary Stream Class Library

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

*/
/*!
\verbatim
	AxPipe.h                        Main class declarations

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-11-23              Initial
\endverbatim
*/

// When AxPipe is made portable, this Windows-stuff must be moved out of here. It's here right now
// to enable code that uses AxPipe to "appear" portable, in that that code at least does not need to
// define and include all this.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN                 ///< Exclude rarely-used stuff from Windows headers
#endif

#ifndef WINVER
#define WINVER 0x0600           // Allow use of features specific to Windows Vista or later.
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600     // Allow use of features specific to Windows Vista or later.
#endif

#ifndef _WIN32_IE
#define _WIN32_IE 0x0600        // Specifies that the minimum required platform is Internet Explorer 6.0.
#endif

//  We include all necessary headers to make this an independent header, even if
//  they usually will be included anyway.

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <assert.h>
#include <tchar.h>
#include <stdlib.h>

// Common base classes
#include "CError.h"
#include "CSeg.h"
#include "CSync.h"
#include "CThread.h"
#include "CCoContext.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "AxPipe.h"

/*! \mainpage AxPipe Multi-Threaded Binary Stream Class Library

	\version
	\htmlinclude Version.txt

	\author
	Svante Seleborg/Axon Data

	\par License:
	\ref License "GNU General Public License"

	AxPipe is a multi-threading basic binary stream class hierarchy.

	It provides all required functionality for push and pull style
	processing of data in a stream model, and it also
	also enables optimizations
	in memory handling, minimizing buffer copying but with full optional multi
	threading support, with negligable overhead.

	The basic paradigm is taken from the Unix Shell pipe notation, where you might
	write:

		crypt <file.txt | compress | tar >out.tar

		but you can also write, for example,

		tar <file.txt | crypt | compress >out.z

	The programs above are semi-ficticious, it's just to demonstrate the principle whereby
	input sources, such as a file can be redirected into a processing program, which
	sends it on, where it can be connected to another processing program, or to a
	final destination.

	I've frequently wanted to use the same principle for programming purposes in C++,
	but with minimal overhead and supporting different programming models. So I
	wrote this package.

	\see \ref PageIntro "Introduction", \ref PageInstall "Installation", \ref PageSample1 "A First Example",
	\ref PageSample2 "A Second Examle",
	\ref PageDef "Definitions of Terms", \ref PageStock "Stock Transformations", \ref PageUtil "Utilities and Overrides"

	Go to the <A HREF="http://sourceforge.net/projects/axpipe">SourceForge project page</A> for downloads etc.
*/

//
//  Use the Windows convention for Unicode/Ansi switcheable code, but if nothing
//  is defined, we default to Ansi here. Change as appropriate if necessary.
//
#ifndef _T
#define _T(s) s                             ///< Default to Ansi. Use tchar.h on Windows.
#define _TCHAR char                         ///< Default to char. Use tchar.h on Windows.
#endif

/// \namespace AxPipe
/// \brief The main namespace where all identifiers should be.
///
/// Use using AxPipe; or AxPipe:: prefix for all references to identifiers
/// except macros in the framework.
namespace AxPipe {
	/// \brief Stock transforms with AxPipe
	///
	/// Stock, or Standard transformations that are part of the
	/// package, but separate from the framework, are collected
	/// for convenience in this namespace. They will be classes
	/// that are derived from the standard AxPipe classes,
	/// implementing specific sources, transformations and sinks.
	namespace Stock {
		// Dummy, just to get the description of the namespace documented.
	}

	/// \brief A minimal safe-pointer class
	///
	/// Define a minimal version of std::auto_ptr, the reason being that
	/// the library version may throw, which we do not want to require all
	/// AxPipe-programs to support.
	template<class T> class my_ptr {
		T* m_p;                             ///< The stored pointer, or NULL
	public:
		/// \brief Construct from pointer
		my_ptr(T* p = NULL) : m_p(p) {}

		/// \brief Assign from one object to this, releasing the the source.
		/// \return A reference to this pointer object
		my_ptr<T>& operator=(my_ptr<T>& rhs) {
			reset(rhs.release());
			return *this;
		}

		/// \brief Delete the object pointed to
		~my_ptr() {
			delete m_p;
		}

		/// \brief Dereference
		/// \return Reference to the pointed to object
		T& operator*() const {
			return (*get());
		}

		/// \brief Get pointer
		/// \return The pointer
		T* operator->() const {
			return get();
		}

		/// \brief Get pointer
		/// \return The pointer
		T* get() const {
			return m_p;
		}

		/// \brief Get the pointer and release it from us
		/// \return The pointer, now unmanaged
		T* release() {
			T* p = m_p;
			m_p = NULL;
			return p;
		}

		/// \brief Store a new poiner, possibly deleting the old
		/// \param p The new pointer
		void reset(T* p = NULL) {
			if (p != m_p) delete m_p;
			m_p = p;
		}
	};

	class CSeg;
	/// Used to keep track of thread fiber-status for the pull-filter mode classes.
	extern DWORD dwTlsIndex;
	/// Keep track of how global initialization count.
	extern volatile long nGlobalInit;
	//
	//  The error class is a virtual base class to all the others,
	//  and is used to record errors. Normally, errors are not passed
	//  by return value, nor are any exceptions thrown.
	//
	//  Use SetError() to indicate an error, and GetError(), to check for one.

	/// ERROR_CODE_GENERIC - for most errors, one string argument.
	extern const _TCHAR* ERROR_MSG_GENERIC;
	/// ERROR_CODE_INTERNAL - for fatal internal errors, one string argument.
	extern const _TCHAR* ERROR_MSG_INTERNAL;
	/// ERROR_CODE_NOTOPEN - Sequence error in operations - need open first.
	extern const _TCHAR* ERROR_MSG_NOTOPEN;

	/// \brief AxPipe pre-defined error codes, gettable with GetErrorCode().
	enum ERROR_CODE {
		ERROR_CODE_SUCCESS = 0,                 ///< No error
		ERROR_CODE_STOP,                        ///< No error - but stop reading source now, we're done.
		ERROR_CODE_GENERIC,                     ///< Use for most error, details in the string argument.
		ERROR_CODE_INTERNAL,                    ///< Used for internal framework errors (bugs).
		ERROR_CODE_NOTOPEN,                     ///< Attempt to do something on a pipe that's not open.
		ERROR_CODE_STOCK,                       ///< An error from a stock transformation
		ERROR_CODE_DERIVED = 100,               ///< Start here for user-derived classes error codes.
	};

	// Modify according to compiler version. Include appropriate #ifdef's.
	typedef __int64 longlong;                   ///< Substitute for long long which is not always supported
	typedef unsigned __int64 ulonglong;         ///< Substitute for unsigned long long which is not always supported
	typedef __int32 int32;						///< Single point of dependency here for 4-byte integer

	/// CSeg's keep track of an opaque segment type meta-data value, which is an int.
	/// User-defined must be non-zero, because the default value is zero. These are
	/// used to mark the special in-band signals for Open, Close and Plug. When we
	/// send CSeg's down the line with a type from this list, the code does special
	/// things, such as calling OutOpen(), OutClose() and Plug() respectively.
	/// \brief Special segment value types that have meaning in the data pump.
	enum eSegType {
		eSegTypeOpen = 1,                       ///< Send signal to open in band
		eSegTypeFlush,                          ///< Send signal to flush in band
		eSegTypeClose,                          ///< Send signal to close in band
		eSegTypePlug,                           ///< Send signal to plug in band
		eSegTypeSignal,                         ///< Send a generic signal. The data is of type CSignal
		eSegTypeDerived = 100,                  ///< Start your own definitions here
	};

	/// \brief The payload of an eSegTypeSignal in-band signal.
	///
	/// A container for data intended for sending via in-band signalling. It is propagated by
	/// the framework, unless a section stops it. There is potential for race conditions if the
	/// data is used outside of the OutSpecial() receiving function, for example storing the contents
	/// in the class and using it later. The differents parts of the pipe line may run in different threads.
	/// The intention is that a receiver will check the Id and if it matches expectations, pick up
	/// the opaque pointer and cast it appropriately for further use. The pointer itself should normally
	/// not be stored by the receiver, unless it is inherently thread safe - i.e. never written to.
	class CSignal : public CCriticalSection {
		void* m_Id;                             ///< A unique identity for the receiver
		void* m_Param;                          ///< An opaque parameter, most likely a pointer
	public:
		/// \brief Construct with unique identity and opaque pointer for the receiver
		CSignal(void* Id = NULL, void* Param = NULL) {
			m_Id = Id;
			m_Param = Param;
		}
		/// \return The unique Id
		void* Id() {
			return m_Id;
		}
		/// \return The opaque parameter
		void* Param() {
			return m_Param;
		}
	};

	/// \brief A custom segment for signalling
	///
	/// Use a CSegSignal segment to send in-band signals downstream. It encapsulates an
	/// ClassId and an opaque parameter pointer, to be used as appropriate by the consumer.
	/// Typical use is Pump(new CSegSignal(aClass::ClassId(), aClass-instance-pointer));
	class CSegSignal : public CSeg {
	public:
		/// \brief Construct with given ClassId and parameter
		/// \param Id A ClassId - typically the pointer to a static variable
		/// \param Param An opaque pointer or parameter. Interpreted by the consumer.
		CSegSignal(void* Id = NULL, void* Param = NULL) : CSeg(sizeof CSignal, new CSignal(Id, Param)) {
			SetType(eSegTypeSignal);
		}

		/// \brief Destruct, deleting the pointer owned by us
		virtual ~CSegSignal() {
			delete (CSignal*)Ptr();
		}

		/// \brief Get a pointer to the CSignal
		/// \return Get a properly cast pointer to the CSignal object
		CSignal* PtrSignal() {
			return (CSignal*)Ptr();
		}
	};

	/// \brief Global initialization for the AxPipe framework.
	///
	/// It's not clear if GetCurrentFiber() is guaranteed to return NULL
	/// before a fiber is created, so to be sure we keep track of it/thread
	/// here.
	///
	/// Can't use __declspec(thread) static as it doesn't work well in delay loaded DLL's
	///
	/// The TLS index is TlsAlloc()'d once per process during run-time startup by
	/// initializing the static. At the same time we register an atexit() function to
	/// handle the TlsFee() of the TLS index.
	///
	/// Can't use static initializers since we sometimes want to use this functionality
	/// without the benefit of run time library support for this, thus we require
	/// the main thread to create an object that initializes all this.
	///
	/// Create exactly one object of type CGlobalInit, and let it destruct on program exit.
	class CGlobalInit {
	private:
		HCRYPTPROV m_hCryptProv;                ///< The random number generator context
	public:
		/// \brief Initialized thread local storage and other global data.
		CGlobalInit() {
			if (InterlockedIncrement(&nGlobalInit) == 1) {
				dwTlsIndex = TlsAlloc();
			}
		}

		/// \brief Free thread local storage.
		~CGlobalInit() {
			if (InterlockedDecrement(&nGlobalInit) == 0 && dwTlsIndex != TLS_OUT_OF_INDEXES) {
				TlsFree(dwTlsIndex);
				dwTlsIndex = TLS_OUT_OF_INDEXES;
			}
		}

		/// \brief Fill buffer with random data
		void Random(void* p, size_t cb) {
			unsigned int r;
			unsigned char* cp = (unsigned char*)p;
			while (cb) {
				rand_s(&r);
				int i = sizeof r;
				while (i-- && cb) {
					*cp++ = (unsigned char)r;
					--cb;
					r >>= 8;
				}
			}
		}
	};

	/// \brief The base class of all CSink and CPipe derived pipe sections.
	///
	/// A CSink should be at the terminating end of all pipe lines, if you
	/// really don't need one, attach a /dev/null equivalent sink, CSinkNull.
	/// (The framework will work anyway, but it's good practice.)
	///
	/// Convention dictates that all CSink derived classes are named with
	/// CSink as a prefix.
	///
	/// CPipe is a derivation of CSink too, basically with the added logic
	/// to send data onwards.
	/// \see CSource
	/// \see CPipe
	/// \see CFilter
	class CSink : public CNoThread, public CError {
		friend class CPipe;                     ///< CPipe needs private access
	protected:
		bool m_fIsOpen;                         ///< Keep track if this part is open
		CSeg* m_pSeg;                           ///< Next/Current segment to work on

	private:
		bool DoSegWork(CSeg* pSeg);             ///< Send a CSeg onwards for processing, handling special types.

	protected:
		void Work();                            ///< Process one CSeg
		CSeg* GetSeg(size_t cb);                ///< Allocate a new segment, possibly from the next section of the pipe.
		virtual void Signal(void* vId, void* p);///< Out of band signalling down stream place holder.
		longlong SizeMax();                     ///< Estimate the final sinks size, if limited.

	public:
		virtual void OutPump(CSeg* pSeg);       ///< Hand off a segment to Work()

	protected:
		virtual longlong OutSizeMax();          ///< Overrideable, Calculate the maximum size of the CSink.
		virtual CSeg* OutGetSeg(size_t cb);     ///< Overrideable, Allocate a CSeg for this sink.
		virtual bool OutSignal(void* vId, void* p); ///< Overrideable, Receive an out of band signal from upstream.
		virtual bool OutOpen();                 ///< Overrideable, Open the data stream for processing
		virtual bool OutFlush();                ///< Overrideable, Handle request for flush of buffered data.
		virtual bool OutClose();                ///< Overrideable, Output any final data, close and prepare for new Open().
		virtual void OutPlug();                 ///< Plug this section.
		virtual bool OutSpecial(CSeg* pSeg);    ///< Overrideable, Consume a special segment.

		/// \brief Overrideable, Consume a segment and Pump() the processed result downstream.
		///
		/// The provided segment is guaranteed to be non-NULL and non-zero-length
		/// A special CSeg with a non-zero AxPipe::eSegType value will be sent to OutSpecial().
		/// This is must be implemented in derived classes, there is no default. For CSink
		/// directly derived class the actual method of consuming it is up to the CSink, for
		/// CPipe derived classes, CPipe::Pump() is the normal method for sending processed
		/// data.
		/// \param pSeg A memory segment to process or consume. CSeg::Release() it when done with it.
		/// \see CPipe::Out()
		/// \see CPipe::Pump()
		/// \see AxPipe::eSegType
		virtual void Out(CSeg* pSeg) = 0;

	public:
		CSink();                                ///< Default constructor.
		virtual ~CSink();                       ///< Clean up.
		virtual void AppendSink(CSink* pSink, bool fAutoDelete); ///< Error catcher.
		virtual void DestructSink();            ///< Destruct code place holder for derived classes.
		virtual void Sync();                    ///< Ensure that all threads downstream are idle
	};
	/// \brief The generic pipe-segment as an abstract class.
	///
	/// All non CSink objects are derived from CPipe, push and pull model
	/// processing segments as well as CSource.
	///
	/// The minimum derived class overrides Out() and processes the CSeg provided,
	/// using the utility member function Pump() to send processed data downstream.
	class CPipe : public CSink {
		friend class CSplit;                    ///< CSplit needs private access.
		void DestructSink();                    ///< The actual destructor code.

	protected:
		CSink* m_pSink;                         ///< Forward pointer to next section downstream.

		void Work();                            ///< Process one memory segment, possibly propagating.
		void AppendSink(CSink* pSink, bool fAutoDelete); ///< Append a section by pointer.
		CSeg* GetSeg(size_t cb);                ///< Utility function, call if you think the next is a CSink that might give you an efficient segment.
		void Signal(void* vId, void* p);        ///< Out of band signalling downstream.
		longlong OutSizeMax();                  ///< Overrideable, Calculate the maximum size of the CSink.
		CSeg* OutGetSeg(size_t cb);             ///< Overrideable, Allocate a writeable CSeg, possibly optimized for the CSink.
		bool OutSignal(void* vId, void* p);     ///< Overrideable, Receive an out of band signal from upstream.
		bool OutOpen();                         ///< Overrideable, Open the data stream for processing
		bool OutClose();                        ///< Overrideable, Output any final data, close and prepare for new Open().
		bool OutSpecial(CSeg* pSeg);            ///< Overrideable, Process a special segment and send results downstream with Pump(). CSeg::Release() it when done with it.

		/// \brief Overrideable, Consume a segment and Pump() the processed result downstream.
		///
		/// The provided segment is guaranteed to be non-NULL and non-zero-length
		/// Special CSeg's with a non-zero eSegType value will be sent to OutSpecial() instead.
		/// Out() must be implemented in derived classes, there is no default. Pump() is the normal
		/// method for sending processed data.
		/// \param pSeg A memory segment to process or consume.
		/// \see Pump()
		void Out(CSeg* pSeg) = 0;

	public:
		CPipe();                                ///< Initialize member variables.
		~CPipe();                               ///< Destruct sink
		CPipe* Append(CSink* pSink);            ///< Append a section by pointer with auto deletion.
		CPipe* Append(CSink& sink);             ///< Append a section by reference.
		void Sync();                            ///< Ensure that all threads downstream are idle
		void Open();                            ///< Utility function, call to open the pipe downstream for output.
		void Pump(CSeg* pSeg);                  ///< Utility function, call typically from Out(), to send a segment downstream.
		void Flush();                           ///< Utility function, call to flush the pipe downstream.
		void Close();                           ///< Utility function, call to close the pipe downstream for output.
	};

	/// \brief /dev/null or NUL: in Windows parlance
	///
	/// A dummy dead-end CSink.
	class CSinkNull : public CSink {
	public:
		/// \brief Consume the given segment, guaranteed to be non-NULL by calling CSeg::Release().
		/// \param pSeg A segment to consume.
		inline void Out(CSeg* pSeg) {
			pSeg->Release();
		}
	};

	/// \brief A forward Y-split, divides a stream into two.
	///
	/// It does nothing more to the data, except pass each segment onwards,
	/// but twice, to each of the streams given ('left' and 'right')
	/// \see CPipe
	class CSplit : public CPipe {
		CPipe* m_pLeft;                         ///< The start of the 'left' side of the split.
		CPipe* m_pRight;                        ///< The start of the 'right' side of the split.

		void DestructSink();                    ///< Always delete the left and right upon deletion of this part.
		void PumpSplit(CSeg* pSeg);             ///< Send the same segment down both left and right legs of the split
	public:
		CSplit();                               ///< Construct and initialize the member variables.
		void AppendSink(CSink* pSink, bool fAutoDelete); ///< Do not append a section, it's an error here.
		void Sync();                            ///< Ensure that all threads downstream are idle
		CSplit* Init(CPipe* pLeft, CPipe* pRight); ///< Initialize split with left and right pointers to pipes.
		void Out(CSeg* pSeg);                   ///< Send the same segment downstream to both parts of the split.
		bool OutSpecial(CSeg* pSeg);            ///< Send the same special segment downstream to both parts of the split.
		bool OutFlush();                        ///< Send a flush signal downstream to both parts of the split.
		bool OutClose();                        ///< Send a close signal downstream to both parts of the split.
		bool OutOpen();                         ///< Send an open signal downstream to both parts of the split.
	};

	/// \brief Accept pushed segments n blocks of m bytes at a time (except last)
	///
	/// Buffer data and work on them in blocks of m bytes. Each segment may be a multiple
	/// of m bytes long. This simplifies working with block oriented data streams or
	/// processes, such as block ciphers. If there's a partial block, it'll be available
	/// from CPipeBlock::BlockPart() when CPipeBlock::OutClose() is called.
	class CPipeBlock : public CPipe {
		CSeg* m_pBlockPart;                     ///< Buffer partial blocks, always m_cbBlockSize in size.
		size_t m_cbBlockSize;                   ///< The size of the blocks in bytes.

	public:
		CPipeBlock();                           ///< Initialize member variables.
		virtual ~CPipeBlock();                  ///< Destruct additional member data.
		CPipeBlock* Init(size_t cbBlockSize);   ///< Set the size of the blocks to be provided to CPipeBlock::Out()
		void OutPump(CSeg* pSeg);               ///< Internal framework override to handle the blocking.
		CSeg* PartialBlock();                   ///< Get the partial block pointer.
	};

	/// \brief A generic source, as an abstract class.
	///
	/// You must override In(), and most likely provide your own constructor as well.
	/// The OutOpen() override shoulde be able to handle multiple calls, with OutClose() inbetween
	/// of course. Once open, Drain() should be called. This will push data from In() downstream
	/// until it signals empty, whereupon a flush is sent. If the source supports it,
	/// Drain() may be called multiple times in a row.
	///
	/// To support usage of multiple sources within a specific pipe, you may
	/// implement the OutClose() and OutOpen() methods, typically to close a file,
	/// and then open a new one, respectively.
	///
	/// Shutdown of the pipe occurs by either calling Plug() explicitly, or by calling it implicitly
	/// from the destructor of the CSource.
	class CSource : public CPipe {
	public:
		virtual ~CSource();                     ///< Ensure Plug() is called.
		CSource* Append(CSink* pSink);          ///< Append a section by pointer with auto deletion.
		CSource* Append(CSink& sink);           ///< Append a section by reference.
		CSource* Open();                        ///< Open the source and possibly propagate downstream
		CSource* Close();                       ///< Close the source and possible propagate downstream
		CSource* Drain();                       ///< Drain the pipe until In() says we're empty for now.
		CSource* Plug();                        ///< Plug this pipe, prepare for exit, cannot reopen after this.
		void Out(CSeg* pSeg);                   ///< Send data to an attached CSink.

	protected:
		/// \brief The basic source of segments
		///
		/// Must override in all CSource derived classes. Should return a memory segment CSeg with
		/// new data as long as there is data available.
		/// \return NULL on error, zero-length on empty/eof, otherwise a CSeg with data.
		virtual CSeg* In() = 0;
	};

	/// \brief /dev/null or NUL: in Windows
	///
	/// A trivial implementation of a CSource that will always return empty/eof
	/// at every read.
	class CSourceNull : public CSource {
	protected:
		/// \brief Always return an empty segment.
		/// \return A pointer to a zero-length CSeg.
		CSeg* In() {
			return new CSeg;
		}
	};

	/// \brief A memory buffer based source
	class CSourceMem : public CSource {
		CSeg* m_pSegSave;                       ///< The one and only segment provided by this class
	protected:
		/// \brief Get the one and only memory buffer the first time, then eof.
		/// \return A CSeg with data or empty to indicate eof, or NULL for error.
		CSeg* In() {
			if (m_pSegSave) {
				m_pSeg = m_pSegSave;
				m_pSegSave = NULL;
				return m_pSeg;
			}
			else {
				return new CSeg;
			}
		}

	public:
		/// \brief Initalize member variables
		CSourceMem() {
			m_pSegSave = NULL;
		}
		/// \brief Initialize with a buffer to read from
		///
		/// We do not take over ownership of the buffer! Keep track of it yourself!
		/// \return A pointer to 'this' CSourceMem
		CSourceMem* Init(size_t cb, const void* p) {
			m_pSegSave = new CSeg(cb, p);
			return this;
		}
	};
	/// \brief  A buffering filter enabling a pull programming-model.
	///
	/// There are some differences in the handling of pull model CFilter based
	/// classes. Flush() has no effect in the pull-model filter.
	///
	/// Instead of overriding Out(), you should override InFilter().
	/// There you use Open(), Read(), Pump() and Close() to perform opening, reading
	/// writing and closing respectively.
	///
	/// When run in the threading version, InFilter() will execute in
	/// a separate thread (as will downstream processing, until a new threaded
	/// section is encountered).
	///
	/// All CFilter derived classes use a co-routine context to handle the reversal
	/// from push to pull model. Essentially we initialize two co-routine contexts,
	/// one for the caller Work(), which calls Out(), and one for InFilter() and Read().
	/// Thus, when a segment arrives (is pushed), we switch to the InFilter context
	/// which will the use Read() to pick up the waiting section. When Read() is then
	/// called to get the next segment, it switches back to the Work co-routine, which
	/// will wait for the next segment to arrive before switching back etc etc.
	class CFilter : public CPipe {
	private:
		bool m_fFirstWork;                      ///< true until first call of Work()
		CCoContext m_ctxFilter;                 ///< The InFilter() co-routine context, a newly created context.

		static void CoFilter(void* pvThis);     ///< Helper static member function to send as StartProc to the CCoContext m_ctxFilter.
		void CoStartFilter(void* pvThis);       ///< The start in-class of the filter co-routine context.
		void Out(CSeg* pSeg);                   ///< Overriden Out() to handle switching to Filter co-routine context.

	public:
		CFilter();                              ///< Initialize member variables.
		~CFilter();

	protected:
		CCoContext m_ctxWork;                   ///< The Work() co-routine context, actually the caller current.

		bool OutOpen();                         ///< Prepare for processing.
		bool OutClose();                        ///< Send a NULL segment close signal to InFilter() and Read().
		bool OutFlush();                        ///< Send flush-request as a zero-length segment to Read()
		void Work();                            ///< Send the m_pSeg segment to the Filter
		CSeg* Read();                           ///< Get a segment, call from InFilter().

		/// \brief The main override in a CFilter derived class.
		///
		/// Override and perform all processing function here. Use Read() to get
		/// data, checking for NULL which indicates that this (sub)stream is empty,
		/// and zero-length segments which indicate a flush request.
		///
		/// Always ensure that Open() get's called before getting any data with Read(),
		/// and that Close() get's called after the last data is read. Also be prepared
		/// to be called multiple times.
		virtual void InFilter() = 0;
	};

	/// \brief A byte-wise filter class, enabling the caller to retrieve one byte at a time.
	///
	/// Use ReadByte() in your implementation of InFilter() to get a byte at a time as an int.
	/// It'll return -1 on eos.
	class CFilterByte : public CFilter {
	protected:
		bool GetNextSeg();                      ///< Helper routine to get next segment.
	protected:
		int ReadByte();                         ///< Read a byte from the stream.
		CSeg* Read();                           ///< Errror catcher, can't call Read() from CFilterByte derived.
		size_t Skip(size_t cb);                 ///< Skip bytes in stream.
	};

	/// \brief A buffering filter class returning chunks of requested size.
	class CFilterBlock : public CFilterByte {
	protected:
		CSeg* ReadBlock(size_t cb);             ///< Attempt to get a segment of a requested size.
	};
	/// \brief A Y join, taking any number of streams and joining them.
	///
	/// Build any number of streams, with CSource's at the start
	/// and any number of CPipe sections, but do not terminate them
	/// with a CSink.
	///
	/// Call Init(int) specifying how many streams you wish to attach to the join.
	///
	/// Get a CSink to terminate them with by calling the GetSink(int) member, with
	/// a sink index as argument. This attaches the stream to the CJoin. If a
	/// stream is started from a separate CSource, use CThreadSource<> to setup
	/// a thread in which to run it.
	///
	/// Override the In() member function to peform custom merging
	/// of many streams into one. They are indexed 0 to n-1. Use
	/// StreamSeg(int) to call the appropriate stream fiber
	/// context. StreamIx(int) to ensure an index is valid. StreamNum()
	/// to get the maximum number of streams and StreamEmpty(int) to check if
	/// an input stream is marked as empty.
	///
	/// The class supports merging of any number of streams.
	class CJoin : public CSource {
		/// \brief A helper class for the merge, each in stream gets a CSinkJoin like this.
		///
		/// The Out() method is overriden to communicate CJoin::In() via thread sync.
		/// CJoin::In() calls CSinkJoin::m_ppInSinks[i].GetSeg(), which waits for
		/// a new segment to arrive from the indexed source, and then provides it.
		class CTSinkJoin : public CThread<CSink> {
			CThreadSync m_Sync;                 ///< Synchronize in streams with worker join thread
			CSeg* m_pNextSeg;                   ///< Communicates the next segment to In().
			bool m_fEmpty;                      ///< Set when a NULL is output, to indicate that it's empty.
		protected:
			void Out(CSeg* pSeg);               ///< Make data available to the CJoin
			bool OutClose();                    ///< Mark input as empty
			bool OutFlush();                    ///< Forward a flush request to the CJoin
		public:
			CTSinkJoin();                       ///< Basic init of members
			CSeg* GetSeg();                     ///< Get the current segment pointer.
			bool IsEmpty();                     ///< True if empty. Obviously.
			void SinkWorkWait();                ///< Wait for this sink make a segment ready via GetSeg().
			void SinkWorkEnd();                 ///< Signal this sink that you've accepted the segment via GetSeg().
		};

		CTSinkJoin** m_ppInSinks;               ///< The array of in-stream control objects.
		int m_nMaxStreams;                      ///< The max number of streams we're prepared for with Init().

	public:
		CJoin();                                ///< Construct the CJoin, but Init() must also be called
		virtual ~CJoin();                       ///< Also destruct all the in stream objects.
		void OutPlug();
		CSink& GetSink(int ix);
		CJoin* Init(int nMaxStreams = 2);       ///< Define how many streams you want here.

		//
		// Utility routines for In()
		//
		CSeg* StreamSeg(int ix);                ///< Get pointer to segment from given stream
		int StreamIx(int ix);                   ///< Reduce ix % StreamNum()
		int StreamNum();                        ///< Get the current number of streams.
		bool StreamEmpty(int ix);               ///< Tell if an indexed stream is marked as empty.
	};

	/*! \page PageIntro Introduction

		AxPipe is suitable when one or more streams of data are to be processed,
		producing one or more streams of output. A pipe line of independent sections
		is built in run-time, with each stage optionally running in it's own thread
		at the programmers discretion.

		\section Background

		AxPipe is useful in all situations where streams of data is
		to be transformed. It grew out of many needs, mostly centered around
		encryption and compression, but it should be useful in many other
		similar cases, such as sound and video codecs and players, hashing,
		splitting, joining, backup, restore, archives and hopefully many
		uses I have not thought about.

		\section Portability

		AxPipe is currently optimized and centered around the Win32 platform. There are
		no fundamental reasons why the framework could not be implemented for Linux as
		well, and I'd appreciate any such contributions and would be glad to incorporate
		them into the main stream code.

		\section Examples

		There's a small first example to study in \ref PageSample1, and a more complex one
		in \ref PageSample2. It may also be helpful to study the AxPipe::Stock transformations,
		as they are some samples of derived filters and pipes, as well as AxPipe::CSourceFileMap
		and AxPipe::CSinkFileMap.

		For a complete real life example, please see the AxDecrypt program, part of the <A HREF="http://www.axantum.com">Xecrets File Classic</A>
		package. Download the source code and examine AxDecrypt.cpp.

		\see \ref PageIntro "Introduction", \ref PageInstall "Installation", \ref PageSample1 "A First Example",
		\ref PageSample2 "A Second Examle",
		\ref PageDef "Definitions of Terms", \ref PageStock "Stock Transformations", \ref PageUtil "Utilities and Overrides"
	*/

	/*! \page PageInstall Installation

		The easiest way to include the library is to include the AxPipe
		project into your solution or workspace. It's configured to work
		as a statically linked library. There is currently no DLL interface,
		and there won't likely be one, it's not that kind of library.

		You should include AxPipe.h at the least, it should be fairly obvious
		what other includes are necessary. Your project should define the
		path to where-ever you placed the AxPipe source code as an extra
		include directory.

		You should normally compile your project with the Multi Threaded
		Run Time Library. AxPipe is configured to, and you'll get a linker
		error message otherwise. If you're sure you won't be using the multi-
		threaded capability you can of course change this to single-threaded,
		but there's no real gain in doing so in most cases.

		AxPipe has one external dependency currently, and that's ZLib. If you
		don't need the AxPipe::Stock::CPipeInflate class, you can mark
		CPipeInflate.cpp as not part of the compile. Optionally, you may also
		choose to include AxPipe on a file-by-file basis directly into your
		own project, and only include those parts that are relevant to you.

		\section ZLib

		The external dependency is to ZLib 1.2.1, you can pick your very own copy
		at http://www.gzip.org/zlib/. The standard project is setup to expect
		a directory named 'Contrib' at the same level as 'AxPipe', and for this
		case a subdirectory named zlib121. In other words, the file CPipeInflate.cpp
		has an additional include directory setup as ../Contrib/zlib121. If there's
		nothing there, and you include CPipeInflate.cpp in the build, you'll get
		a compilation error about zlib.h not found.

		\see \ref PageIntro "Introduction", \ref PageInstall "Installation", \ref PageSample1 "A First Example",
		\ref PageSample2 "A Second Examle",
		\ref PageDef "Definitions of Terms", \ref PageStock "Stock Transformations", \ref PageUtil "Utilities and Overrides"

	*/
	/*! \page PageStock Stock Transformations

		The idea in the long term is to collect a number of transformations that
		are wrapped by this framework, so that authors may combine in new
		combinations. Look to the project site, http://axpipe.sourceforge.net for
		available AxPipe::Stock transforms, and do please submit your own!

		\see \ref PageIntro "Introduction", \ref PageInstall "Installation", \ref PageSample1 "A First Example",
		\ref PageSample2 "A Second Examle",
		\ref PageDef "Definitions of Terms", \ref PageStock "Stock Transformations", \ref PageUtil "Utilities and Overrides"

	*/
	/*! \page PageDef Definitions of Terms

		- Pipe, Pipe line: The code that processes a data stream using the
		AxPipe framework. It is built from at
		least 2 to an unlimited number of sections. All pipe lines generally
		begin with a AxPipe::CSource, and end with a AxPipe::CSink.

		- Source: AxPipe::CSource's are intended to provide data for the pipe (stream), for
		example by reading from a file.

		- Section: In between, there can be many processing steps based on AxPipe::CPipe and AxPipe::CFilter,
		and also some more elaborate constuctions such as multi-pipe AxPipe::CJoin:s and AxPipe::CSplit:s.

		- Sink: AxPipe::CSink's are intended to store the data that is the result of the
		processing, for example into a file.

		\section DataMovement Data Movement

		The native model for data movement is the push model. This means that data is read from
		the AxPipe::CSource, and then pushed down the pipe, i.e. the subsequent sections are called
		with each respective segment as they are read. This model is suited for simple processing
		with few or no input states.

		The pull model is also supported in AxPipe::CFilter derived classes. In this model your code will
		request data by a member function call, which returns with requested data when available. This is suitable
		for more complex parsing where perhaps many possible input states exist.

		\section DataUnit Data Unit

		The basic unit of data is a AxPipe::CSeg object, which is a reference counted memory buffer
		object of (size_t limited) arbitrary size. Code written for AxPipe should usually not depend on
		CSeg objects being of any particular size, except in derived classes where such guarantees
		are provided.

		\see \ref PageIntro "Introduction", \ref PageInstall "Installation", \ref PageSample1 "A First Example",
		\ref PageSample2 "A Second Examle",
		\ref PageDef "Definitions of Terms", \ref PageStock "Stock Transformations", \ref PageUtil "Utilities and Overrides"
	*/
	/*! \page PageSample1 A First Example

		This is almost the smallest complete AxPipe program possible, sort of the equivalent of the
		standard 'Hello World' first program.

		It does nothing, except move data from one source, through a pipe section, to a destination.
		But even so, it's probably a fair performing file copier, since the source and destination
		are memory mapped files, and execute in different threads in this example. What will happen
		is that the source file is mapped into memory, section by section, and a pointer to that
		memory mapping is passed to the destination, where it is copied into the correspondingly
		mapped section of the destination file. Thus, the file copy is reduced to one more more
		memcpy() calls + actually mapping them to memory.

		\include HelloWorld.cpp

		\see \ref PageIntro "Introduction", \ref PageInstall "Installation", \ref PageSample1 "A First Example",
		\ref PageSample2 "A Second Examle",
		\ref PageDef "Definitions of Terms", \ref PageStock "Stock Transformations", \ref PageUtil "Utilities and Overrides"
	*/
	/*! \page PageSample2 A Second Example

		The following is a sample program with some patterns to re-use.
		It will build a pipe
		reading from a file, and process the input in three stages, demonstrating
		three different basic models.
		It will also join two sources, and then split them up again, just to demonstrate
		the use of that functionality.

		The assumption is that the input data is ASCII, just to make it clear.

		The first stage changes all spaces (' ') to dashes ('-')<BR>
		The second stage changes all dashes ('-') to plus ('+')<BR>
		The third stage changes all plus ('+') to equal ('=')<BR>

		The join, just simply takes one segment from each source and output it, in a round-
		robin fashion.

		The split finally, will take every other character and pass them to two different
		sinks, one being standard output, the other being a file.

		Not very useful perhaps, but it demonstrates the principles involved. Actually, for regular
		text streams, the iostream library may be a better bet (although it does not support
		threading).

		<HR>
		First we define a new type of source, reading from standard input.
		\dontinclude Demo.cpp
		\skip CSourceStdin
		\until // CSourceStdin

		Here we just override CSource::In() and read in suitable chunks, passing
		it onwards by returning the a CSeg with the data. That's the basic
		source. For files, use the included CSourceMemFile.

		<HR>
		Then we define a new type of sink, writing to standard output.
		\skip CSinkStdout
		\until // CSinkStdout

		This is almost trivial, override CSink::Out and write the CSeg segment
		passed.

		<HR>
		The first sample uses a segment oriented push model.
		It demonstrate how to build the basic type of AxPipe::CPipe derived
		push-model stream processor.<BR>
		\skip CPipeReplace1
		\until // CPipeReplace1
		The heart of the example is in the override of CPipe::Out. Segments are
		passed to it as they arrive, a new segment is allocated, and is used to
		create the processed result. This is then sent onwards with CPipe::Pump.
		The input segment, which now is no longer needed, is CSeg::Release'd.

		<HR>
		The second examle uses the pull-model instead, where the code requests
		segments instead until the end of stream is detected.
		\skip CPipeReplace2
		\until // CPipeReplace2
		Here we override CFilter::InFilter, and request segments with CFilter::Read.
		In other respects, it's the same as the previous example.<BR>
		Do note that a CFilter-derived class in it's CFilter::InFilter, must
		explicitly call CFilter::Open and CFilter::Close. This can be changed
		by overriding the default CFilter::OutOpen and CFilter::OutClose, which
		do nothing but stop the propagation of the open and close signals from
		the source in the default versions. More about open and close in the
		description of the main code.

		<HR>
		The final example here illustrates the use of a further derivation of the
		filter model, providing a byte at a time.
		\skip CPipeReplace3
		\until // CPipeReplace3
		It's the same override of CFilterByte::InFilter, but now the CFilterByte::ReadByte
		function is called, providing a byte at a time, or -1 at the end of the
		stream. Here also we need to call CFilterByte::Open and CFilterByte::Close.

		<HR>
		A rudimentary join, which will just intermix any number of streams, on a segment
		by segment basis, round-robin fashion. This is not very useful either, as the
		segmentation will depend on the previous stages and is not known here.
		\skip CJoinInterMix
		\until // CJoinInterMix
		Note that to actually get anything to join, you must use the CJoin::GetSink() member
		and CSource::Append() that to a pipe.

		<HR>
		A class used in the splitting, but also serves as yet another example of a simple
		push-model processing stage. This takes either the odd-numbered or the even-numbered
		bytes of a stream and passes them on, dropping the other bytes.
		\skip CEvenOdd
		\until // CEvenOdd
		See the code in _tmain() below for an example of how to use AxPipe::CSplit together
		with this kind of class.

		<HR>
		Finally, the main program tying it all together.
		\skip _tmain
		\until // _tmain
		First, note the definition of a CGlobalInit object. You need one, and only one,
		such object to be defined in your program before using ::AxPipe. The constructor
		of this object will initialize various global data.<BR>

		The second thing to note is the Open()->Drain()->Close()->Plug() sequence.<BR>
		The CSource::Drain() call causes data to be read from the CSource and passed along
		the pipe to the CSink. But before that, you must call CSource::Open(). This causes
		a signal to be passed down the line, enabling sources, pipe sections and
		sinks to prepare. After the source signals end of stream, the CSource::Close() call
		is necessary to give the different parts a chance to flush final data etc.

		Also note how the extra AxPipe::CSource derived objects are setup to drain
		in threads of their own. This is necessary for the CJoinInterMix to work, as it
		otherwise will simply wait for data. Do remember thus, that using a AxPipe::CJoin
		derived class entails many threads by definition.

		It's possible to re-open a pipe-line by calling CSource::Open() again, if the
		sections support it. This is suitable for situations where a single
		stream contains of separate concatenated parts for example.

		The final CSource::Plug call close the pipe-line for good.

		A check for errors is done by calling CSource::GetErrorCode, any error
		signalled with CError::SetError will be passed back to the source and
		thus be checked here. If there is an error, the CSource::GetErrorMsg will
		get the text representation of it.
		<HR>

		Do follow the links provided for explanation of the different framework calls.

		\see CSeg, CThread, CSource, CSink, CPipe, CFilter, CFilterByte, CFilterBlock
		CPipeBlock, CJoin, CSplit, AxPipe::CSourceFileMap, AxPipe::CSinkFileMap

		\see \ref PageIntro "Introduction", \ref PageInstall "Installation", \ref PageSample1 "A First Example",
		\ref PageSample2 "A Second Examle",
		\ref PageDef "Definitions of Terms", \ref PageStock "Stock Transformations", \ref PageUtil "Utilities and Overrides"
	*/
	/*! \page PageUtil Utility and Overrideable Functions

		Use the basic components and then derive
		custom classes to perform whatever data transformation, condensation
		or generation needed.

		\section Utility Utility functions
		The framework provides a number of functions that are intended to be called by
		code in user derived classes. You should normally not override these implementions,
		but just call them when appropriate. See the section on Overrides below.
		The most important are:

		- AxPipe::CPipe::Open() A data stream must be opened before processing. It may be opened
		and closed any number of times from construction to destruction via AxPipe::CSource::Plug().
		- AxPipe::CPipe::Flush() Send a voluntary request to flush buffered data downstream.
		- AxPipe::CPipe::Close() Ends the current processing of data, and prepares for a Open() call again.
		- AxPipe::CPipe::Signal() Send an out of band signal to downstream objects.
		- AxPipe::CPipe::Pump() Send data downstream after processing.
		- AxPipe::CFilter::Read() Get data for processing in pull model AxPipe::CFilter based derived classes.
		- AxPipe::CError::SetError() Report an error, also causing processing to end and the CSource to
		simulate and end of stream situation to end processing.

		\section Overrides Overrideable functions
		Most utility functions above have a corresponding overrideable virtual implementation. The
		utility function calls really just wrap the actual implementations and handle propagation
		downstream or upstream in the case of errors.

		Most overrides have the same name as the utility function, but prefixed with Out, such as:

		- AxPipe::CPipe::Out() The actual processing in a push model AxPipe::CPipe derived class.
		- AxPipe::CPipe::OutOpen() Actually do what is required to open the stream.
		- AxPipe::CPipe::OutFlush() Actually do what is required to flush buffered data.
		- AxPipe::CPipe::OutClose() Close the stream, prepare for new AxPipe::CPipe::OutOpen().
		- AxPipe::CPipe::OutSignal() Receive an out of band signal, and check if it's relevant to this object.
		- AxPipe::CFilter::InFilter() The actual processing in a AxPipe::CFilter derived class.

		In most cases you should call the base class implementation as part of the derived implementation.

		\section Constructors Non-default Constructors

		Due to the way the framework is to be used, you should not provide anything but
		elaborations on the default constructor in your derived classes. When you neeed
		further initialization, please use and call a separate member function like
		the following:

		\code
		public:
			CPipeMyDerivation *Init(...) {
				...
				return this;
			}
		\endcode

		\section Threading

		To enable threading any CSink or CSource-derived class, use the template CThread
		as a wrapper, for example:

		\code
		pipe->Append(new CThread<CPipeReplace>);    // Run in a separate thread
		\endcode

		Note that the threaded class and all that follow it down the pipe are run in the
		same thread, unless a new threaded class is appended to the chain.

		\section Naming Naming Conventions

		A convention is to name derived classes with the prefix CPipe, CSplit, CJoin, CSink
		or CSource before the rest of the name. CPipe is used for all kinds of intermediate
		transformations. If it's a threading version, and you define the class explicitly,
		name it CTPipe, CTSplit etc.

		AxPipe::CSeg pointers are usually named pSeg or variants thereof.

		\see \ref PageIntro "Introduction", \ref PageInstall "Installation", \ref PageSample1 "A First Example",
		\ref PageSample2 "A Second Examle",
		\ref PageDef "Definitions of Terms", \ref PageStock "Stock Transformations", \ref PageUtil "Utilities and Overrides"
	*/
} // namespace AxPipe
#endif
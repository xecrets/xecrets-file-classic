#pragma once
#ifndef AXPIPE_CTHREAD_H
#define AXPIPE_CTHREAD_H
/*! \file CThread.h
	\brief Threading dummy base and template wrapper AxPipe::CNoThread and AxPipe::CThread<>

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
	CThread.h                       Threading dummy base and template wrapper

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-05              Initial
\endverbatim
*/
#include "AxPipe.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CThread.h"

namespace AxPipe {
	using AxLib::OutputDebugStringF;

	/// \brief Dummy non-threaded base-class for all CSource, CSink and CPipe derived classes.
	/// \see CSource
	/// \see CSink
	/// \see CPipe
	/// \see CThread
	///
	/// Mostly placeholders in the case we later derive from CThread, in which case the virtuals
	/// here get overridden with real thread-handling and synchronizating functionality. Some
	/// basic code that is common is defined here.
	class CNoThread {
	protected:
		bool m_fExit;                           ///< Set to true when the derived object is to exit.
		bool m_fAutoDeleteSink;                 ///< Set to true if the derived object's sink is to self-destruct with the pipe-line.

		/// \brief Initalize one Work-cycle, processing one CSeg.
		virtual void WorkStart() {
		}
		/// \brief Start Work() on one CSeg.
		virtual void WorkSignal() {
			Work();
		}
		/// \brief End one Work-cycle.
		virtual void WorkEnd() {
		}
		/// \brief Wait for a new CSeg to arrive to work on.
		virtual void WorkWait() {
		}
		/// \brief Wait for the Work()-thread, if any, to terminate.
		virtual void WorkExitWait() {
		}
		/// \brief Actually process one CSeg.
		virtual void Work() = 0;
	public:
		CNoThread() {
			m_fAutoDeleteSink = m_fExit = false;
		}
		/// \brief Wait for the Work() thread to finish if it's processing.
		///
		/// Defined here, but only has function in threaded version.
		/// Start and End one Work cycle, thereby ensuring that the
		/// previous one has finished.
		void WaitForIdle() {
			WorkStart();
			WorkEnd();
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
		static void* ClassId() {
			static int i;
			return &i;
		}

		/// \brief Run-Time version of our type identification.
		/// \see ClassId()
		virtual void* RTClassId() {
			return ClassId();
		}
	};

	/// \brief Only used as a ThreadProc to get back into the class.
	/// \param lpParam The 'this' pointer of the class where this is run.
	//static inline DWORD WINAPI CThreadProc(LPVOID lpParam);

#pragma warning (push)
// Disable 'this' : used in base member initializer list
#pragma warning (disable: 4355)
/// \brief Template to implement a pipe-section in a separate thread.
///
/// The basic thread mechanism revolves around a number of virtual
/// functions that are overriden here, such as
/// Work(). All synchronization etc is handled by the class, and
/// the Work() function is called in it's own thread.
///
/// To enable threading use the appropriate CSource, CPipe or CSink derived
/// class as the argument.
/// \param T A CSource, CPipe or CSink derived class to run in a separate thread.
	template <class T> class CThreadNoRun : public CThreadMain<T> {
		CThreadSync m_ThreadSync;               ///< Implement worker thread synchronization.

	public:

		/// \brief Wait for the worker thread to terminate, then close handles etc.
		virtual ~CThreadNoRun() {
			if (!m_fExit) {
				SetError(ERROR_CODE_INTERNAL, ERROR_MSG_INTERNAL, _T("CThread::~CThread Exit() not called"));
			}
		}

	public:
		/// \brief Initiate one Work() cycle - called from outside worker thread.
		void WorkStart() {
			m_ThreadSync.WorkStart();
		}

		/// \brief Signal that we've prepared for more Work() - called from outside worker thread.
		void WorkSignal() {
			m_ThreadSync.WorkSignal();
		}

		/// \brief Wait for more to be ready for Work() - this is called in the worker thread.
		void WorkWait() {
			m_ThreadSync.WorkWait();
		}

		/// \brief End one Work() cycle - called from the worker thread.
		void WorkEnd() {
			m_ThreadSync.WorkEnd();
		}

		/// \brief Wait for the Work()-thread, if any, to terminate.
		virtual void WorkExitWait() {
			Wait();
		}
	};

	/// \brief Thread wrapper for AxPipe CSource, CPipe and CSink derived classes.
	///
	/// Setup a thread, start it running and pump data through the Work() member
	/// function, using thread synchronization. Basically all Out* and In* functions
	/// will run in the context of this separate thread.
	template <class T> class CThread : public CThreadNoRun<T> {
	public:
		CThread() {
			Run();
		}
	private:
		/// \brief The ThreadProc for the worker thread
		/// \return Always 0, not the thread exit code.
		virtual int Main() {
			OutputDebugStringF(_T("CThread()::Main() ID=%X\n"), GetCurrentThreadId());
			while (!m_fExit) {
				// Elesewhere WorkStart() and WorkSignal() will be called
				WorkWait();                     // Wait for more to do
				Work();
				WorkEnd();
			}
			OutputDebugStringF(_T("CThread()::Main() ID=%X WaitForIdle()...\n"), GetCurrentThreadId());
			WaitForIdle();                      // Ensure that the last work is done.
			// This is to handle a memory leak bug in Win32, where an exiting
			// thread being a fibre does not clean up after itself. See Q185231 or KB185231.
			// Update 2005-05-20: And the really, really great thing is they fixed the bug in Windows Server 2003,
			// causing the delete by the system to result in a double free on the heap and making the program
			// crash! So the fix breaks the documented work-around - and there is no documented way to determine
			// if the fix is in or not! Aaaaarghhhh. What to do? We let the memory leak.
			//
			// If we have successfully allocated a TLS index
			if (AxPipe::dwTlsIndex != TLS_OUT_OF_INDEXES) {
				// If we have converted this thread into a fiber
				if (TlsGetValue(AxPipe::dwTlsIndex) != NULL) {
					// Then we do the free to avoid the memory leak as per above.
					//See above! ::LocalFree(GetCurrentFiber());
				}
			}
			OutputDebugStringF(_T("CThread()::Main() ...exiting thread ID=%X\n"), GetCurrentThreadId());
			return 0;
		}
	};

	/// \brief Start a CSource in a separate thread.
	/// A CSource derived class will be setup to Drain() in
	/// it's own thread.
	/// \see Main()
	/// \param T A CSource derived class to start in it's own thread.
	template <class T> class CThreadSource : public CThreadMain<T> {
	private:
		/// \brief The ThreadProc for the worker thread
		/// Do Open()->Drain()->Close()->Plug();
		/// \return Always 0, not the thread exit code.
		virtual int Main() {
			Open()->Drain()->Close()->Plug();
			return 0;
		}
	};

#pragma warning (pop)
}; // namespace AxPipe
#endif AXPIPE_CTHREAD_H

#pragma once
#ifndef AXPIPE_CSYNC_H
#define AXPIPE_CSYNC_H
/*! \file CSync.h
	\brief Thread synchronization class AxPipe::CSync

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

	Why is this framework released as GPL and not LGPL?
	See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	CSync.h                         Thread synchronization class

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-05              Initial
\endverbatim
*/
#include "AxPipe.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CSync.h"

namespace AxPipe {
	/// \brief Provide single-process mutual exclusion synchronization
	///
	/// This is typically used as an additional base class for objects that need
	/// assured mutually exclusive access. Specifically CSignal objects derive from this.
	class CCriticalSection {
	private:
		int m_iLockCount;
		CRITICAL_SECTION cs;

	public:
		CCriticalSection() {
			InitializeCriticalSection(&cs);
			m_iLockCount = 0;
		}

	public:
		~CCriticalSection() {
			DeleteCriticalSection(&cs);
		}

	public:
		/// \brief Get lock, or wait until we do get it. It's ok to call multiple times.
		void GetLock() {
			EnterCriticalSection(&cs);
			m_iLockCount++;
		}

	public:
		/// \brief Release lock. We must have it. Must release the same number as we get locks.
		void ReleaseLock() {
			m_iLockCount--;
			LeaveCriticalSection(&cs);
		}

	public:
		/// \brief Create an instance of this class in a block that needs exclusive access.
		template<class T> class Lock {
			T* m_pcs;

		public:
			Lock(T* pcs) {
				ASSPTR(pcs);
				if ((m_pcs = pcs) != NULL) {
					pcs->GetLock();
				}
			}

		public:
			void ReleaseLock() {
				if (m_pcs != NULL) {
					m_pcs->ReleaseLock();
					m_pcs = NULL;
				}
			}

		public:
			~Lock() {
				if (m_pcs != NULL) {
					m_pcs->ReleaseLock();
				}
			}
		};
	};
	/// \brief Thread synchronization.
	///
	/// Event-based thread synchronization.
	class CSync {
	private:
		HANDLE m_hEvent;                        ///< The event object to synchronize with.
	public:
		CSync();                                ///< Create the event.
		~CSync();                               ///< Close the event.
		bool Wait(int iMs = -1);                ///< Wait for someone to call Signal() for iMs milliseconds.
		bool Signal();                          ///< Send a signal to someone who's waiting with Wait().
	};
	/// \brief A small collection of objects and methods for thread sync
	///
	/// Threads often need synchronized access to shared data, and control
	/// the the passing of the data. This class implements methods for this
	/// under a 'work' paradigm. Thread A wants to pass off a piece of work
	/// in some form of shared medium, i.e. shared memory for example, to
	/// thread B. The sequence is then:
	///     A                                   B
	///                                         ...
	///                                         WorkWait()
	///     ...
	///     WorkStart()
	///     WorkSignal()
	///                                         ...
	///                                         WorkEnd()
	///
	/// The methods ensure that when WorkStart() returns, no other thread is between
	/// WorkStart() and WorkEnd(). It's also guaranteed that when WorkSignal()
	/// returns, thread B has received the signal via WorkWait(). Owneship of the
	/// shared resource passes from A to B upon return from WorkSignal() and WorkWait()
	/// respectively. Thread B relinquishes it's hold, upon call to WorkEnd(), and as
	/// previously noted Thread A get's ownership upon return of WorkStart().
	class CThreadSync {
		HANDLE m_hSemaphore;                    ///< Enable serialization of requests for processing, can't use a Mutex, as it's sometimes the same thread we need to control
		CSync m_Work,                           ///< Signal when worker has work to do.
			m_Accepted;                       ///< Signal when worker has accepted signal.
	public:
		CThreadSync();                          ///< Initialize sync objects
		~CThreadSync();                         ///< Clean up
		void WorkStart();                       ///< Initiate one Work() cycle
		void WorkSignal();                      ///< Signal that we've prepared for more Work()
		void WorkWait();                        ///< Wait for more to be ready for Work()
		void WorkEnd();                         /// End one Work() cycle
	};

	/// \brief a Template class that will create a thread for a method virtual int Main()
	template <class T> class CThreadMain : public T {
		DWORD m_dwThreadId;                     ///< The ThreadId of the started thread.
		HANDLE m_hThread;                       ///< Handle to the worker thread.
	private:
		/// \brief static helper to get back into the class after starting the thread
		/// Calls the virtual Main(), returns the result of that as the thread exit code.
		/// \param lpParam the 'this' pointer of the class containing the worker thread.
		static DWORD WINAPI Main(LPVOID lpParam) {
			return ((CThreadMain<T>*)lpParam)->Main();
		}

		/// \brief The main() of the thread, derived classes must override
		///
		/// A separate thread will be started, calling this function and
		/// returning it's return value as the thread exit code.
		///
		/// \return The thread exit code
		virtual int Main() {
			ASSERR(_T("Override of 'virtual int Main()' missing"));
			return 0;
		}
	public:
		/// \brief Create thread and set priority.
		///
		/// The thread will not start, it is created initially suspended. Use
		/// CThreadMain::Run() to start it.
		CThreadMain() {
			// As we can't set a proper process prio below 2k version, we manually inherit current
			// thread priority.
			int iCurPrio = GetThreadPriority(GetCurrentThread());
			ASSAPI((m_hThread = CreateThread(NULL, 0, Main, this, CREATE_SUSPENDED, &m_dwThreadId)) != NULL);
			SetThreadPriority(m_hThread, iCurPrio);
		}

		/// \brief Wait for the worker thread to terminate, then close handles etc.
		virtual ~CThreadMain() {
			ASSAPI(WaitForSingleObject(m_hThread, INFINITE) == WAIT_OBJECT_0);
			ASSAPI(CloseHandle(m_hThread));
		}

		/// \brief Start the thread running
		void Run() {
			ResumeThread(m_hThread);
		}

		/// \brief Wait for the worker thread to end - called from outside worker thread, Obviously.
		void Wait() {
			WaitForSingleObject(m_hThread, INFINITE);
		}
	};
}; // namespace AxPipe
#endif AXPIPE_CSYNC_H

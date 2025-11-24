/*! \file
	\brief Implementation of AxPipe::CCoContext, co-routine context holder object for Win32

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
	CCoContext.cpp                  Implementation of CCoContext, co-routine context holder object for Win32

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CCoContext.cpp"

namespace AxPipe {
	/// \brief Create a new co-routine context.
	///
	/// Construct a new context or, with a StartProc and a parameter to send it,
	/// or if no pfStart is provided, the currently executing context will be initalized
	/// to be the co-routine context.
	/// In either case it won't actually start at StartProc until Go() is called.
	/// \param pErr Pointer to an CError derived object where we can send errors.
	/// \param pfStart Pointer to a StartProc routine.
	/// \param pvParam An opaque argument to StartProc, probably a 'this' pointer.
	CCoContext::CCoContext(CError* pErr, void (*pfStart)(void*), void* pvParam) {
		m_pFiber = NULL;
		Init(pErr, pfStart, pvParam);
	}

	/// \brief Initalize the error object pointer, the StartProc and the param
	/// \param pErr Pointer to an CError derived object where we can send errors.
	/// \param pfStart Pointer to a StartProc routine.
	/// \param pvParam An opaque argument to StartProc, probably a 'this' pointer.
	void
		CCoContext::Init(CError* pErr, void (*pfStart)(void*), void* pvParam) {
		m_pErr = pErr;
		m_pfStart = pfStart;
		m_pvParam = pvParam;
	}

	/// \brief Stop this context.
	///
	/// Don't destruct this object from it's own context. If you do, and it's not the
	/// original context, it's an error. If it is the original context, nothing happens
	/// and the original thread must exit and clean up all by itself.
	CCoContext::~CCoContext() {
		Stop();
	}

	/// \brief Helper for the CreateFiber call, needs a static callback, this is it.
	VOID CALLBACK
		CCoContext::Start(PVOID lpParam) {
		((CCoContext*)lpParam)->m_pfStart(((CCoContext*)lpParam)->m_pvParam);
		// Should never get here.
	}

	/// \brief Switch to this objects coroutine context.
	/// If it's the first call to an instance of the current context, then
	/// initialize the object to the current context instead. If it has a StartProc
	/// and it's the first call, then we start that, otherwise we just switch back
	/// to that co-routines context.
	///
	/// From the point of view of the caller of Go(), it'll look like any procedure call,
	/// Go() will execute and then return to the caller, but not when it executes 'return',
	/// but when that code executes a Go() to the co-routine context of the caller.
	/// \return true if we successfully switched and got back.
	bool
		CCoContext::Go() {
		// First assure we really do have a TLS index. If we don't - this is
		// an error condition.
		if (dwTlsIndex == TLS_OUT_OF_INDEXES) {
			m_pErr->SetError(ERROR_CODE_INTERNAL, ERROR_MSG_INTERNAL, _T("CoContext::Go() [No TLS available]"));
			return false;
		}
		// If this is the first call to Go() - i.e. initialize
		if (!m_pFiber) {
			m_dwThreadId = GetCurrentThreadId();
			// If we're to initialize in the current context
			if (!m_pfStart) {
				//OutputDebugString(_T("CCoContext::Go() !m_pfStart Init in current context\n"));
				// If we're not a fiber, we need to convert to one.
				if (TlsGetValue(dwTlsIndex) == NULL) {
					//OutputDebugString(_T("CCoContext::Go() ConvertThreadToFiber(0)\n"));
					m_pFiber = ConvertThreadToFiber(0);
					// And now we've converted to one, we need to remember that this thread
					// is now a fiber. If we have TLS, we set the value to true to inidcate this.
					TlsSetValue(dwTlsIndex, (LPVOID)true);
				}
				else {
					//OutputDebugString(_T("CCoContext::Go() GetCurrentFiber()\n"));
					m_pFiber = GetCurrentFiber();
				}
				// Now m_pFiber is the current fiber.

				// We must guard against effectively doing SwitchToFiber(GetCurrentFiber())
				// Since we're just initializing this context, and want to remain here,
				// we just do a return.
				return true;
			}
			// We're to create a new fiber with a specific starting point, so
			// let's do that.
			//OutputDebugString(_T("CCoContext::Go() CreateFiber(0, Start, this)\n"));
			m_pFiber = CreateFiber(0, Start, this);
			// ...we fall through below to actually start the fiber too.
		}
		// Here the thread must have been converted to a fiber, to allow the switch.
		ASSCHK(TlsGetValue(dwTlsIndex) != NULL, _T("CoContext::Go() [Attempt to switch to fiber from non-fiber]"));
		//        ASSCHK(m_dwThreadId == GetCurrentThreadId(), _T("CoContext::Go() [Attempt to schedule fiber in different thread]"));
				//OutputDebugString(_T("CCoContext::Go() SwitchToFiber()\n"));
		SwitchToFiber(m_pFiber);
		// Now we're back, because someone switched to us
		return true;
	}

	/// \brief Stop and delete a co-routine context state.
	///
	/// If we have a fiber context, and it was not made from the then current context,
	/// and it's not ourselves that are running, we delete the fiber.
	///
	/// (Otherwise, it must be the thread's responsibility to clean up and delete
	///  the initial fiber of a thread. This will happen automatically when the
	///  thread exits.)
	void
		CCoContext::Stop() {
		// If we have a StartProc and we have a fiber...
		if (m_pFiber && m_pfStart) {
			// ...and this fiber is not the current fiber...
			if (m_pFiber != GetCurrentFiber()) {
				// ... then we delete it, and forget it.
				DeleteFiber(m_pFiber);
				m_pFiber = NULL;
			}
			else {
				// ... otherwise we're trying to stop ourselves, which we can't do.
				ASSERR(_T("Attempting to stop self"));
			}
		}
	}
};
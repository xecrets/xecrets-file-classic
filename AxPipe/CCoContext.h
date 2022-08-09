#pragma once
#ifndef AXPIPE_CCOCONTEXT_H
#define AXPIPE_CCOCONTEXT_H
/*! \file
	\brief Co-routine context class wrapper

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
	CCoContext.h                    Co-routine context class wrapper

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-08              Initial
\endverbatim
*/
#include "AxPipe.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CCoContext.h"

namespace AxPipe {
	/// \brief Encapsulate a co-routine context.
	///
	/// A co-routine is a context that executes along with other co-routines
	/// in the same process and thread, but with it's own stack, registers and
	/// program counter - sort of a very light weight thread, but with no
	/// independent scheduling, and by definition no concurrent or parallell
	/// execution.
	///
	/// In Windows Win32, this concept is called a 'fiber'.
	/// A CCoContext can be initalized to represent the already executing current
	/// context, or to create a new execution context. In most cases you first
	/// want to make a context represent the current context, then create a new
	/// context, that can then switch back to the original and then back again as
	/// needed.
	///
	/// The constructors may be called in any context. No creation or switching
	/// of contexts are done there.
	///
	/// Each CCoContext object thus represents one co-routine context in a thread.
	class CCoContext {
		DWORD m_dwThreadId;                     ///< The thread we started the fiber in.
		LPVOID m_pFiber;                        ///< This objects co-routine state

		void (*m_pfStart)(void*);              ///< Pointer to a StartProc
		void* m_pvParam;                        ///< The parameter sent to the StartProc
		CError* m_pErr;                         ///< Point to an object where we can report an error.

	public:
		/// \brief Create a new co-routine context.
		CCoContext(CError* pErr = NULL, void (*pfStart)(void*) = NULL, void* pvParam = NULL);
		/// \brief Initalize the error object pointer, the StartProc and the param
		void Init(CError* pErr, void (*pfStart)(void*), void* pvParam);

		~CCoContext();                          ///< Stop this context.
		static VOID CALLBACK Start(PVOID lpParam); ///< Helper for the CreateFiber call, needs a static callback, this is it.
		bool Go();                              ///< Switch to this objects coroutine context.
		void Stop();                            ///< Stop and delete a co-routine context state.
	}; // class CCoContext
}; // namespace AxPipe
#endif AXPIPE_CTHREAD_H

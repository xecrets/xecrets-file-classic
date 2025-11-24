#pragma once
#ifndef AXPIPE_CERROR_H
#define AXPIPE_CERROR_H
/*! \file
	\brief Handle backward error propagation etc.

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
	CError.h                        Handle backward error propagation etc.

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-05              Initial
\endverbatim
*/
#include "AxPipe.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CError.h"

namespace AxPipe {
	/// \brief Base class to all segments, handles backwards error propagation etc.
	///
	/// The most commonly used members in derived classes are SetError() to
	/// report an error and GetErrorCode() and GetErrorMsg() to check for errors
	/// after plugging the pipe, and getting the error description if needed.
	class CError {
	private:
		CError* m_pPrev;                        ///< Point back to previous in pipe. NULL if Source.
		_TCHAR* m_szError;                      ///< Allocated message, only valid in Source. NULL otherwise.
		int m_iError;                           ///< Error code, only valid in Source. Success otherwise.

		/// Pass the string backwards to the source, where we store it.
		void InError(int iError, _TCHAR* szError);

	protected:
		void Init(CError* pPrev);                ///< Used internally to initialize the pointer to previous. Don't call.

	public:
		CError();                               ///< Just initialize the member variables.
		~CError();                              ///< Delete the error message, if there is one.

		/// Signal an error from derived classes.
		void SetError(int iError, const _TCHAR* szError, const _TCHAR* szParam = NULL);

		_TCHAR* GetErrorMsg();                  ///< Retrieve an error message, if any.
		int GetErrorCode();                     ///< Retrieve the error code, if any.
	};
}; // namespace AxPipe
#endif AXPIPE_CERROR_H

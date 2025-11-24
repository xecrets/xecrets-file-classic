/*! \file CError.cpp
	\brief Implementation of AxPipe::CError error handler

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
	CError.cpp                      Implementation of CError error handler

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-11-23              Initial
\endverbatim
*/
#include "stdafx.h"
#include "CError.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CError.cpp"

namespace AxPipe {
	/// \brief Pass the string backwards to the source, where we store it.
	void
		CError::InError(int iError, _TCHAR* szError) {
		if (m_pPrev) {
			m_pPrev->InError(iError, szError);
		}
		else {
			if (m_iError != ERROR_CODE_SUCCESS) {
				delete[] szError;           // Free the message, won't happen otherwise
				return;                     // Always keep the first error reported, assume it's the 'root' cause
			}
			delete[] m_szError;             // If there happens to be something before...
			m_szError = szError;
			m_iError = iError;
		}
	}
	/// \brief Used internally to initialize the pointer to previous. Don't call.
	void
		CError::Init(CError* pPrev) {
		m_pPrev = pPrev;
	}
	/// \brief Just initialize the member variables.
	CError::CError() {
		m_szError = NULL;
		m_pPrev = NULL;
		m_iError = ERROR_CODE_SUCCESS;
	}
	/// \brief Delete the error message, if there is one.
	CError::~CError() {
		delete[] m_szError;
	}
	/// \param iError The error code, see AxPipe::ERROR_CODE
	/// \param szError An error message, you may use AxPipe::ERROR_MSG_INTERNAL and AxPipe::ERROR_MSG_GENERIC as well as any string.
	/// \param szParam If the error message contains a printf %s, this string is inserted there in the message.
	void
		CError::SetError(int iError, const _TCHAR* szError, const _TCHAR* szParam) {
		// wsprintf has a hard-coded limit of 1024.
		_TCHAR* szFmtError = new _TCHAR[1024];
		if (szFmtError) {
			// Use wprintf so as not to include the c-run time library version, for size.
			wsprintf(szFmtError, szError, szParam);
			InError(iError, szFmtError);
		}
	}
	/// Call using any object in a pipe, it will backtrace to the source
	/// and report the error code there.
	/// \return The text of an error message, or NULL if none. Treat this as a static (it's not).
	_TCHAR*
		CError::GetErrorMsg() {
		if (m_pPrev) {
			return m_pPrev->GetErrorMsg();
		}
		else {
			return m_szError;
		}
	}
	/// Retrieve an error code, or AxPipe::ERROR_CODE_SUCCESS if no error.
	/// This may be called using any object in a pipe, it will backtrace to the source
	/// and report the error code there.
	int
		CError::GetErrorCode() {
		if (m_pPrev) {
			return m_pPrev->GetErrorCode();
		}
		else {
			return m_iError;
		}
	}
};
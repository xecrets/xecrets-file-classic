// This is always undefined here, so we always can #define it after inclusion of this header.
// You may, and should, include in every file where you use the assert macros.
#ifdef AXLIB_ASSERT_FILE
#undef AXLIB_ASSERT_FILE
#endif

#ifndef AXLIB_ASSERT
#define AXLIB_ASSERT
/*! \file
	\brief Fatal assertions and formatted message box etc.

	@(#) $Id$

	Copyright (C) 2001-2022 Svante Seleborg/Axon Data, All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:support@axantum.com and http://www.axantum.com
----
	AxAssert.h

	E-mail                          YYYY-MM-DD              Reason
	support@axantum.com             2003-11-22              Initial

*/

#include <tchar.h>

#ifndef ASSCHK
/// \brief Assert any custom condition
///
/// Do the if to ensure that the condition is evaluted before the call AssFunc, so that parameters
/// depending on that is properly passed to the function
/// \param fOk An expression that must validate to 'true'
/// \param sz A string with a message about the assertion.
#define ASSCHK(fOk, sz) if (!(fOk)) AxLib::AssFunc(false, sz, _T(AXLIB_ASSERT_FILE), __LINE__)
#endif

#ifndef ASSERR
/// \brief Assert always unconditionally
///
/// \param sz A string with a message about the assertion.
#define ASSERR(sz) AxLib::AssFunc(false, sz, _T(AXLIB_ASSERT_FILE), __LINE__)
#endif

#ifndef ASSAPI
/// \brief Assert the result from a Win32 API operation.
///
/// It should be called immediately after using a Win32 API function that may
/// fail, and that sets the GetLastError() error code.
/// The message shown will use the message defintion from Windows.
/// Do the if to ensure that the condition is evaluted before the call to LastErrorMsg()
/// \param fOk An expression that must validate to TRUE
#define ASSAPI(fOk) if (!(fOk)) AxLib::AssFunc(false, AxLib::LastErrorMsg(), _T(AXLIB_ASSERT_FILE), __LINE__)
#endif

#ifndef ASSPTR
/// \brief Assert that a pointer is non-NULL
/// \param p A pointer expression that must not be NULL
#define ASSPTR(p) AxLib::AssFunc((p) != NULL, _T("NULL pointer"), _T(AXLIB_ASSERT_FILE), __LINE__)
#endif

namespace AxLib {
	/// \brief Some assert-definintions, and a debug-printf using a MessageBox
	///
	/// Use asserts where you want to assert(sic!) a condition, and if it it's not
	/// ok, there's no use to continue execution. All Ass* 'functions' here will
	/// exit() after displaying a message - so this is for fatal errors, such as
	/// internal inconstencies, end of memory conditions, unexpected and un-manageable
	/// Win32-API returns etc.
	///
	/// Macros #ASSCHK, #ASSAPI and #ASSPTR are used to actually call the function
	/// so as to get the correct file and line into the message produced.

	/// \brief Get last Win32 API error as static text string.
	extern const _TCHAR* LastErrorMsg();
	/// \brief Get a string representation of the most recent system error
	extern _TCHAR* APerror(const _TCHAR* sz = NULL);
	/// \brief Display formatted message on failed assertion and exit
	extern void AssFunc(bool fOk, const _TCHAR* sz, const _TCHAR* szFile, int iLine);
	/// \brief A MessageBox() with printf() functionality
	extern void MessageBoxF(const _TCHAR* szFmt, const _TCHAR* szCaption, unsigned int uType, ...);
#ifdef _DEBUG
	/// \brief A OutputDebugString() with printf() functionality
	extern void OutputDebugStringF(const _TCHAR* szFmt, ...);
#else
	/// \brief A OutputDebugString() with printf() functionality
	inline void OutputDebugStringF(const _TCHAR* szFmt, ...) { szFmt; }
#endif
} // namespace AxLib

#endif
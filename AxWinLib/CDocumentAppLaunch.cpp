/*! \file
	\brief Implement launch-and-wait functionality for a document.

	@(#) $Id$

	Copyright (C) 2006-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

	This program is free software; you can redistribute it and/or modify it under the terms
	of the GNU General Public License as published by the Free Software Foundation;
	either version 2 of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along with this program;
	if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
	Boston, MA 02111-1307 USA

	The author may be reached at mailto:svante@axantum.com and http://wwww.axantum.com
----
	CDocumentAppLaunch.cpp
*/
#include "stdafx.h"

#include <string>

#include "IDocumentAppLaunch.h"

namespace awl {
	class CDocumentAppLaunch : public IDocumentAppLaunch {
		std::wstring m_ErrorMessage;

	public:
		CDocumentAppLaunch() : m_ErrorMessage() {
		}

		/// \brief Launch the app and wait.
		/// \param wzDocumentPath The full path to the document.
		/// \return true if all went well.
		virtual bool LaunchAndWait(const wchar_t* wzDocumentPath) {
			m_ErrorMessage = L"Not Yet Implemented";
			return false;
		}

		/// \brief If an error, an error message is kept here.
		/// \return The error message, or an empty string.
		virtual const wchar_t* ErrorMessage() {
			return m_ErrorMessage.c_str();
		}

		virtual ~CDocumentAppLaunch() {
		}
	};

	/// \brief Create an instance of CDocumentAppLaunch
	IDocumentAppLaunch* IDocumentAppLaunch::New() {
		return new CDocumentAppLaunch();
	}
}
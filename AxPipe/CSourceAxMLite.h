#pragma once
/*! \file
	\brief Declaration of AxPipe::Stock::CSourceAxMLite

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
	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2004-09-12              Initial
\endverbatim
*/
#include "AxPipe.h"
#include "../AxWinLib/AxMLite.h"

namespace AxPipe {
	namespace Stock {
		/// \brief produce a XML-stream from an XMLite XML object
		class CSourceAxMLite : public CSourceMem {
			axpl::ttstring m_xml;                      ///< The string representation of the XML
		public:
			CSourceAxMLite() : CSourceMem() {
			}

			CSourceAxMLite* Init(XNode* pXNode) {
				m_xml = pXNode->GetXML();
				CSourceMem::Init(m_xml.size() * sizeof(m_xml[0]), m_xml.data());
				return this;
			}
		};
	} // namespace Stock;
} // namespace AxPipe;
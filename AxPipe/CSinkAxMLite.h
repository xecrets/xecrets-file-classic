#pragma once
/*! \file
	\brief Declaration of AxPipe::Stock::CSinkAxMLite

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
	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2004-09-12              Initial
\endverbatim
*/
#include "AxPipe.h"
#include "../AxWinLib/AxMLite.h"
#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CSinkAxMLite.h"

namespace AxPipe {
	namespace Stock {
		/// \brief Accept a data stream, and at the end parse it to a XMLite tree structure.
		class CSinkAxMLite : public CSink {
		private:
			XNode* m_pXNode;                        ///< Root of the parsed XML-tree
			AxPipe::CSeg* m_pXML;                   ///< This is where we accumulate all the XML
			size_t m_cbAlloc;                       ///< Bytes to allocate per go
			size_t m_cbSize;                        ///< Bytes of XML in the buffer
			bool m_fOpen;                           ///< True if we are in an open state
		public:
			/// \brief Initialize and allocate buffers etc.
			CSinkAxMLite() : m_pXNode(NULL), m_pXML(NULL), m_cbSize(0), m_fOpen(false) {
				Init(m_pXNode);
			}
			/// \brief Initialize with the root to use.
			/// The sink buffers all XML until the end, then it is parsed.
			/// Specify a suitable allocation increment, and optionall a
			/// tree to start with - or NULL.
			/// \param pXNode A pointer to a tree - we take over ownership
			/// \param cbAlloc Allocate memory in these increments
			/// \return self
			CSinkAxMLite* Init(XNode* pXNode = NULL, size_t cbAlloc = 0x1000) {
				Delete();                           // Ensure clean slate
				m_pXNode = pXNode;                  // Set the new pointer
				m_cbAlloc = cbAlloc;                // Remember default alloc increment
				Grow();
				return this;
			}

			/// \brief Clean up buffers etc.
			void Delete() {
				// Clean up any old root pointer
				if (m_pXNode) {
					delete m_pXNode;
					m_pXNode = NULL;
				}
				// Clean up any old XML in-memory buffer pointer
				if (m_pXML != NULL) {
					m_pXML->Release();
					m_pXML = NULL;
					m_cbSize = 0;
				}
			}

			/// \brief Get the root of the parsed XML-tree
			/// \return The root, but don't delete it - we still own it.
			XNode* GetXNode() {
				return m_pXNode;
			}

			/// \brief Get and release the root of the parsed XML-tree
			/// \return The root - do remember to delete it - we don't have it any more.
			XNode* ReleaseXNode() {
				XNode* p = m_pXNode;
				m_pXNode = NULL;
				return p;
			}

			/// \brief Clean up owned pointers etc.
			virtual ~CSinkAxMLite() {
				Delete();
			}

			/// \brief Grow the size of the XML buffer
			/// \return The newly grown buffer, with the old data copied there.
			CSeg* Grow() {
				CSeg* pNew = new CSeg((m_pXML == NULL ? 0 : m_pXML->Len()) + m_cbAlloc);
				ASSPTR(pNew);
				if (m_pXML) {
					memcpy(pNew->PtrWr(), m_pXML->PtrRd(), m_pXML->Len());
				}
				return m_pXML = pNew;
			}

		protected:
			bool OutOpen() {
				Delete();
				Grow();
				m_fOpen = true;
				return CSink::OutOpen();
			}

			/// \brief Accept and append a segment
			void Out(CSeg* pSeg) {
				if (!m_fOpen) {
					SetError(ERROR_CODE_NOTOPEN, _T("CSinkXMLite::Out() Not Open!"));
					return;
				}
				while (m_cbSize + pSeg->Len() > m_pXML->Size()) {
					Grow();
				}
				memcpy(m_pXML->PtrWr() + m_cbSize, pSeg->PtrRd(), pSeg->Len());
				m_cbSize += pSeg->Len();
				pSeg->Release();
			}

			/// \brief Actually process the XML
			bool OutClose() {
				if (m_fOpen) {
					if (!m_pXNode) {
						m_pXNode = new XNode;
						ASSPTR(m_pXNode);
					}
					// Check for non-zero length
					if (m_cbSize) {
						// Check for non-nul termination - if so, add one
						if (m_pXML->PtrRd()[m_cbSize - 1]) {
							// Check for room for the nul
							if (m_pXML->Size() == m_cbSize) {
								Grow();
							}
							m_pXML->PtrWr()[m_cbSize++] = '\0';
						}
						// At this point we have loaded something we know is in 8-bit Ansi representation, but the XML
						// parser expects a generic text mapping array, which means we may need to translate to Unicode.
						// Now parse and load the nul-terminated XML-representation in memory
						if (!m_pXNode->Load(axpl::s2t((char*)m_pXML->PtrRd()).c_str())) {
							SetError(ERROR_CODE_GENERIC, _T("XMLite Parse Failed"));
						}
					}
					m_fOpen = false;
				}
				return CSink::OutClose();
			}
		};
	} // namespace Stock;
} // namespace AxPipe;
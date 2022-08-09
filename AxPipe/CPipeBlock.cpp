/*! \file
	\brief Implementation of AxPipe::CPipeBlock, providing pushed blocks of a given size.

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

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	CPipeBlock.cpp                  Implementation of CPipeBlock, providing pushed blocks of a given size.

	E-mail                          YYYY-MM-DD              Reason
	axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "CPipeBlock.cpp"

namespace AxPipe {
	/// \brief Initialize member variables.
	CPipeBlock::CPipeBlock() {
		Init(0);
	}

	/// \brief Destruct additional member data.
	CPipeBlock::~CPipeBlock() {
		if (m_pBlockPart) {
			m_pBlockPart->Release();
		}
	}

	/// \brief Set the size of the blocks to be provided to CPipeBlock::Out()
	/// \param cbBlockSize The size in bytes of the blocks to be provided.
	CPipeBlock*
		CPipeBlock::Init(size_t cbBlockSize) {
		m_cbBlockSize = cbBlockSize;
		m_pBlockPart = NULL;
		return this;
	}

	/// \brief Internal framework override to handle the blocking.
	///
	/// Ensures that Out() will only be called with segments a multiple of the
	/// m_cbBlockSize.
	/// \param pSeg The segment provided from upstream that we preprocess to ensure the blocking.
	void
		CPipeBlock::OutPump(CSeg* pSeg) {
		// Propagate end of stream, and exit directly. We can never have a full output-block
		// waiting at this stage, if it's end of stream - this will have to be picked up by
		// the OutClose() function. It might also be a special block, those we send as-is.
		if (!CSeg::IsSeg(pSeg)) {
			CPipe::OutPump(pSeg);
			return;
		}

		if (m_pBlockPart) {
			size_t cbToMove = m_cbBlockSize - m_pBlockPart->Len();

			// Adjust if we don't get enough for a full block
			if (cbToMove > pSeg->Len()) {
				cbToMove = pSeg->Len();
			}
			CopyMemory(&m_pBlockPart->PtrWr()[m_pBlockPart->Len()], pSeg->PtrRd(), cbToMove);
			m_pBlockPart->Len(m_pBlockPart->Len() + cbToMove);
			pSeg->Drop(cbToMove);

			// If we do have a block
			if (m_pBlockPart->Len() == m_cbBlockSize) {
				CPipe::OutPump(m_pBlockPart);
				m_pBlockPart = NULL;
			}
		}
		// Now we know that m_pBlockPart is NULL, let see if we can send more.

		// Now output as much as possible. Create a clone, and make it an even multiple of
		// the block size in length. Only do it if there's enough for at least a block.
		if (pSeg->Len() >= m_cbBlockSize) {
			CSeg* pBlockSeg = pSeg->Clone();
			pBlockSeg->Len(pSeg->Len() - pSeg->Len() % m_cbBlockSize);
			pSeg->Drop(pBlockSeg->Len());
			CPipe::OutPump(pBlockSeg);
		}

		if (pSeg->Len()) {
			// There's a partial block left, make a new segment, one block large, and put it there.
			m_pBlockPart = new CSeg(pSeg->PtrRd(), pSeg->Len(), m_cbBlockSize - pSeg->Len());
		}
		pSeg->Release();
	}

	/// \brief Get the partial block pointer.
	///
	/// Call from your derived OutFlush() and/or OutClose(), depending on your semantics
	/// if you want to handle a final partial block.
	/// \return Pointer to partial block, or NULL if none.
	CSeg*
		CPipeBlock::PartialBlock() {
		return m_pBlockPart;
	}
};
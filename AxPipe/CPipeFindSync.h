#pragma once
/*! \file
	\brief AxPipe::Stock::CPipeFindSync, Find a sync and start passing data then.

	@(#) $Id$

	AxPipe - Binary Stream Framework

	Copyright (C) 2003-2023 Svante Seleborg/Axon Data, All rights reserved.

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
	axpipe@axondata.se              2003-12-10              Initial
\endverbatim
*/
namespace AxPipe {
	namespace Stock {
		class CPipeFindSync;
	}
}

/// \brief Scan a stream for a sync-sequence, skipping until found
///
/// Find sync and start or stop passing it on from that point. The default is
/// to start passing data after the first sync that is found, but
/// it's possible to specify how many to skip. The actual sync sequence
/// is not passed along, only the data following it. In some cases it
/// may be necessary to bit-flip the pattern before compare, do
/// specify in the call to Init().
class AxPipe::Stock::CPipeFindSync : public AxPipe::CPipe {
	int m_iSkipTo;                          ///< Number of GUID's to skip + 1.
	const unsigned char* m_pPattern;        ///< Ptr to the pattern to search for
	size_t m_cbPattern;                     ///< Length of pattern
	size_t m_iNext;                         ///< Index of next byte to match in pattern
	int m_iInvert;                          ///< Flag set to 1 if we are to bit-flip the pattern
	bool m_fSkipAfterSync;                  ///< Determine what happens after we've sync'd-

	void PumpBuf(size_t cbBuf);             ///< Re-generate early parts of the sync sequence
protected:
	void Out(AxPipe::CSeg* pSeg);           ///< Accept pushed data and skip until sync

public:
	/// \brief Set the sync sequence to look for
	CPipeFindSync* Init(const void* p, size_t cb, bool fInvert = false, int iSkipTo = 1);
};

/*! \file
    \brief Implementation of AxPipe::Stock::CPipeFindSync, skip until sync

    @(#) $Id$

    AxPipe - Binary Stream Framework

    Copyright (C) 2003 Svante Seleborg/Axon Data, All rights reserved.

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
    E-mail                          YYYY-MM-DD              Reason
    axpipe@axondata.se              2003-12-01              Initial
\endverbatim
*/
#include "stdafx.h"
#include "CPipeFindSync.h"

/// Initialize the pattern to sync with. Note that the we only save a reference
/// to the pattern, so it must not be destructed before this object.
/// Use a negative value of iSkipTo to indicate that you'd like to pass data
/// _until_ the given number of patterns are detected.
/// \param p The pattern, do not destruct before this object.
/// \param cb The length of the pattern in p
/// \param fInvert Set to true if the pattern should be bitflipped before comparison
/// \param iSkipTo The number of syncs to find before starting/stopping pass-through
/// \return A pointer to 'this'
AxPipe::Stock::CPipeFindSync *
AxPipe::Stock::CPipeFindSync::Init(const void *p, size_t cb, bool fInvert, int iSkipTo) {
    m_pPattern = (const unsigned char *)p;
    m_cbPattern = cb;
    m_iNext = 0;
    m_fSkipAfterSync = ((m_iSkipTo = iSkipTo) < 0);
    if (m_fSkipAfterSync) {
        m_iSkipTo = -m_iSkipTo;
    }
    m_iInvert = fInvert ? 0xff : 0;

    return this;
}
/// Regenerate a partial sync sequence that we've already passed
/// \param cbMunched The number of sync sequence bytes to re-generate
void AxPipe::Stock::CPipeFindSync::PumpBuf(size_t cbBuf) {
    if (cbBuf) {
        CSeg *pBufSeg = new CSeg(m_pPattern, cbBuf);
        for (size_t i = 0; i < cbBuf; i++) {
            pBufSeg->PtrWr()[i] ^= m_iInvert;
        }
        Pump(pBufSeg);
        pBufSeg = NULL;
    }
}

/// Accepted segements of pushed data, skipping m_iSkipTo number of occurrences of
/// of the pattern represented by m_pPattern and m_cbPattern before starting to
/// to pass segments through.
/// \param pSeg The AxPipe::CSeg that contains the next data segment
void AxPipe::Stock::CPipeFindSync::Out(AxPipe::CSeg *pSeg) {
    // Already matched the right number of patterns?
    if (!m_iSkipTo) {
        if (m_fSkipAfterSync) {
            // Already skipping
            pSeg->Release();
        } else {
            // We've already matched the required number, so let's send it onwards
            Pump(pSeg);
        }
        return;
    }
    // Step one byte at a time, attempting to find a match. The pattern buffer
    // serves a dual purpose - to record previously seen, and matched, bytes
    // and of course to serve as the comparison to find matches. The idea is that
    // we do not need to store previous matched bytes, since they by definition
    // must be a part of the pattern - otherwise they should be output or skipped.
    // m_iNext keeps track of the next byte we want to match in the pattern.
    const unsigned char *pData = pSeg->PtrRd();
    size_t cbDataRemain = pSeg->Len();  // Can't be zero
    size_t iPrevBuf = m_iNext;          // Number of old bytes from previous segment(s)
    size_t iOutPrevBuf = 0;             // Number of old bytes not part of buffer after this seg

    // While more data to compare against the pattern
    while (cbDataRemain--) {
        // If we still have a pattern match
        if (*pData++ == (m_pPattern[m_iNext] ^ m_iInvert)) {
            m_iNext++;
            if (m_iNext == m_cbPattern) {
                // If we've matched the entire pattern - bingo!
                if (--m_iSkipTo) {
                    // Still not zero. Must match more patterns.
                    m_iNext = 0;
                } else {
                    // Now we've found the right number of syncs.
                    // Reduce the length so that data including and after this found sync
                    // is not part of the segment to pump. This is calculated by first reducing
                    // the length by cbDataRemain (these are the bytes after the sync).
                    // Then we either reduce by a whole sync length, or by the partial length
                    // we had to start with.
                    // cbDataRemain is only updated to the start of the matched sequence
                    if (m_fSkipAfterSync) {
                        // Pump what we've got so far, and start skipping....
                        Pump(pSeg->Len(pSeg->Len() - (cbDataRemain + (m_cbPattern - iPrevBuf))));
                    } else {
                        // Drop all up until the start of this sequence, then start...
                        PumpBuf(iPrevBuf);
                        Pump(pSeg->Drop(pSeg->Len() - (cbDataRemain + (m_cbPattern - iPrevBuf))));
                    }
                    return;
                }
            }
        } else {
            if (m_iNext) {
                size_t i;
                for (i = 0; i < m_iNext; i++) {
                    if (iPrevBuf) {
                        iPrevBuf--;
                        iOutPrevBuf++;
                    }
                    if (i && (memcmp(m_pPattern, &m_pPattern[i], m_iNext - i) == 0)) {
                        break;
                    }
                }
                m_iNext -= i;
                continue;
            }
        }
    }
    if (m_fSkipAfterSync) {
        // Pump 'i' bytes that were buffered, but no match.
        PumpBuf(iOutPrevBuf);

        // Pump the whole segment, except for newly buffered bytes, if any.
        Pump(pSeg->Len(pSeg->Len() - (m_iNext - iPrevBuf)));
    } else {
        // We're to skip before sync, and since we've exhausted this seg,
        // we just drop it.
        pSeg->Release();
    }
}

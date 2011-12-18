/*! \file
    \brief HashKey.cpp - Hash a given passphrase and/or key-file

    @(#) $Id$

    HashKey.cpp - Hash a given passphrase and/or key-file

    Copyright (C) 2005 Svante Seleborg/Axantum Software AB, All rights reserved.

    This program is free software; you can redistribute it and/or modify it under the terms
    of the GNU General Public License as published by the Free Software Foundation;
    either version 2 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program;
    if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
    Boston, MA 02111-1307 USA

    The author may be reached at mailto:axcrypt@axantum.com and http://axcrypt.sourceforge.net

    Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
    YYYY-MM-DD              Reason
    2005-10-28              Initial
\endverbatim
*/
#include "stdafx.h"

#include <memory>

extern "C" {
#include "AxCryptLib.h"
}
#include "AxCryptLibPP.h"
#include "BlockTypes.h"
#include "../AxPipe/AxPipe.h"
#include "../AxPipe/CFileIO.h"
#include "../AxPipe/CPipeSHA1.h"

#include "Assert.h"
#define ASSERT_FILE "HashKey.cpp"

namespace axcl {
    /// \brief Send both a string and contents of a file downstream
    /// First send the contents of a 'char' string, then the contents
    /// of a file (if there is any).
    class CAxCryptKeySeq : public AxPipe::CSourceFileIO {
        /// \brief The passphrase to start sending
        std::auto_ptr<unsigned char> m_pPassphrase;
        size_t m_cbPassphrase;

        bool m_fHaveFile;                       ///< true if we got a file name to send too
      
    public:
        /// \brief Initialize private members.
        CAxCryptKeySeq() : m_fHaveFile(false), m_pPassphrase(NULL), m_cbPassphrase(0) {
        }

        /// \brief Store a copy of the passphrase, and init the file source if any
        /// \param szPassphrase A char string
        /// \param szKeyFileName The name of a file to also pass data from (after the string)
        /// \param cbChunk The size of the chunks to work with
        /// \return A pointer to 'this'
        CAxCryptKeySeq *Init(const unsigned char *pPassphrase, size_t cb, const _TCHAR *szKeyFileName, size_t cbChunk = 1024) {
            m_pPassphrase.reset(axcl::arrdup<unsigned char>(pPassphrase, cb));
            m_cbPassphrase = cb;

            if (m_fHaveFile = (szKeyFileName != NULL && szKeyFileName[0] != '\0')) {
                CSourceFileIO::Init(szKeyFileName, cbChunk);
            }
            return this;
        }

        /// \brief Open the file stream if any, otherwise just return true
        bool OutOpen() {
            return m_fHaveFile ? CSourceFileIO::OutOpen() : true;
        }

        /// \brief Close the file stream if any, otherwise just return true
        bool OutClose() {
            return m_fHaveFile ? CSourceFileIO::OutClose() : true;
        }

        /// \brief Start sending the passphrase string, then contents of the file
        /// \return A segment, first the string then from the file if any
        AxPipe::CSeg *In() {
            if (m_pPassphrase.get() != NULL && m_cbPassphrase) {
                AxPipe::CSeg *pSeg = new AxPipe::CSeg(m_pPassphrase.get(), m_cbPassphrase);
                // We only use it once, so release it here and mark it as empty
                static_cast<void>(m_pPassphrase.release());
                m_cbPassphrase = 0;
                return pSeg;
            }
            // If it's a zero-length passphrase, we just fall through
            return m_fHaveFile ? CSourceFileIO::In() : new AxPipe::CSeg;
        }
    };
}

/// \brief Hash a key, storing the result and fingerprint in the indicated key location in the parameter block
///
/// Hash a key, generate a fingerprint, and store the result. The passphrase is here treated as a sequence of
/// bytes. Unicode/Ansi issues must be handled by the caller, by simply hashing both variants for decryption,
/// and deciding which version to use for encryption.
/// \param pParam The parameter block to store the result
/// \param iKeyType The name of the key to store to (AXCL_KEY_ENC/AXCL_KEY_DEC)
/// \param pPassphrase Pointer to a sequence of bytes to use as a passprase or NULL
/// \param cbPassphrase The number of bytes in the passphrase
/// \param szKeyFullPath The full path to a key-file to append to the passphrase in the hash
/// \return A status code, AXCL_E_OK (zero) if no error
int axcl_HashKey(AXCL_PARAM *pParam, int iKeyType, const unsigned char *pPassphrase, size_t cbPassphrase, const _TCHAR *szKeyFullPath) {
    // Hash the contents of the key and the key-file (if any).
    AxPipe::Stock::CPipeSHA1 SHA1;
    std::auto_ptr<axcl::CAxCryptKeySeq> pSource(new axcl::CAxCryptKeySeq);
    pSource->Init(pPassphrase, cbPassphrase, szKeyFullPath, pParam->cbChunkSize)->Append(SHA1)->Append(new AxPipe::CSinkNull)->Open()->Drain()->Close()->Plug();
    ASSCHK(pSource->GetErrorCode() == 0, pSource->GetErrorMsg());

    axcl::THash h;
    axcl::TKey k;

    memcpy(pParam->keys[iKeyType].pKEK, SHA1.GetHash(), pParam->keys[iKeyType].cbKEK);
    std::auto_ptr<axcl::TFingerprint> pFingerprint(new axcl::TFingerprint(pParam->keys[iKeyType].pKEK, pParam->keys[iKeyType].cbKEK));
    memcpy(pParam->keys[iKeyType].pFingerprint, pFingerprint.get(), pParam->keys[iKeyType].cbFingerprint);

    return AXCL_E_OK;
}

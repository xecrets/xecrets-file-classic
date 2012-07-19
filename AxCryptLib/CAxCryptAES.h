#ifndef CAXCRYPTAES_H
#define CAXCRYPTAES_H
/*! \file
    \brief CAxCryptAES.h - An Ax Crypt special purpose AES-wrapper

    @(#) $Id$

    CAxCryptAES.h - An Ax Crypt special purpose AES-wrapper

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

    The author may be reached at mailto:software@axantum.com and http://www.axantum.com
----
*/

extern "C" {
#include "AxCryptLib.h"
}
#include "AxCryptLibPP.h"
#include "BlockTypes.h"

#include "Assert.h"
#define ASSERT_FILE "CAxCryptAES.h"

namespace axcl {
/// \brief Simple wrapper class for the AES-code.
///
///  A major reason to do our own wrapper instead of using existing code is that
///  we need to ensure that keys and round keys are kept in dynamically allocated
///  storage that we know is safe. (This requires that the 'new' and 'delete' operators
///  are redefined to guarantuee the safety of the data in whatever way is deemed
///  appropriate).
///
///  The Init Vector is never secret - so we keep it in regular memory.
///
///  To get full control we only use the low-level algoritm parts.
///
///  This class is not a complete API - it only implements exactly the modes
///  needed by Ax Crypt.
///
///  Please note that padding must be done external to this code - we only
///  handle whole blocks here.
///
class CAxCryptAES {
public:
    /// \brief Parameter values to control the algorithm direction
    enum etDirection {
        eEncrypt,                           ///< Use in constructor or Init()
        eDecrypt                            ///< Use in constructor or Init()
    };
    /// \brief Parameter values to control the supported modes
    enum etMode {
        eECB,                               ///< Use in constructor or Init(). Electronic Code Book mode.
        eCBC                                ///< Use in constructor or Init(). Cipher Block Chaining mode.
    };
    /// \brief Parameter values to control the key-length used
    enum etKeyLength {
        eKey128Bits,                        ///< Use in constructor or Init().
        eKey192Bits,                        ///< Use in constructor or Init().
        eKey256Bits                         ///< Use in constructor or Init().
    };

    /// \brief If used, must set parameters with Init().
    CAxCryptAES();
    ~CAxCryptAES();
    /// \brief Construct and set all parameters.
    CAxCryptAES(const TKey *putKey, etMode eMode, etDirection eDirection, etKeyLength eKeyLength = eKey128Bits);
    /// \brief Set all parameters.
    void Init(const TKey *putKey, etMode eMode, etDirection eDirection, etKeyLength eKeyLength = eKey128Bits);
    /// \brief Copy IV
    void SetIV(const TBlock *putIV);
    /// \brief Transform one or more blocks.
    bool Xblock(const TBlock *putSrc, TBlock *putDst, size_t nBlocks = 1);
private:
    uint32 *m_pdwRoundKeys;                 ///< Round-keys are allocated - easier to upgrade to var lengths. 4*10 = 40x32 bits. 128-bit keys use 10-rounds.
    TBlock m_utIV;                          ///< Init Vector - updated in CBC-mode
    int m_iNr;                              ///< Number of rounds
    bool m_bStateOk;                        ///< true if init ok.
    etDirection m_eDirection;               ///< Keep track of tranformation direction...
    enum etMode m_eMode;                    ///< ...and keep track of transformation mode...
    enum etKeyLength m_eKeyLength;          ///< ...and keep track of transformation key length
};

/// \brief  Generate subkeys for various uses.
///
/// This class has two main purposes:
///
/// 1 - to avoid conflicts caused by using the same subkey in different contexts.
/// 2 - to isolate knowledge of relationship between key-size and block-size.
///
/// Exposing one or more subkeys must not endanger either the other subkeys, or the
/// master key. In fact, the eValidator key is exposed in the file, and never used
/// for actual encryption.
class CAxCryptAESSubKey {
private:
    TKey *m_pSubKey;                        ///< The generated sub-key
public:
    /// \brief Enumeration of the various sub-keys we can generate
    enum etSubKey {
        eHMAC,                              ///< The HMAC sub-key
        eValidator,                         ///< Not used. Is there to keep the enumeration values constant.
        eHeaders,                           ///< The header encryption sub-key
        eData                               ///< The actual data-encrypting sub-key
    };

    CAxCryptAESSubKey();
    ~CAxCryptAESSubKey();

    /// \brief Generate a sub-key, given a master key
    CAxCryptAESSubKey& Set(TKey *pMasterKey, etSubKey eSubKey);
    /// \brief Get the generated sub-key.
    TKey *Get();
};

/// \brief Implement the FIPS-recommended Key Wrapping algorithm with AES.
///
/// This is a self-checking iterative transformation, that can also be
/// used as a work-factor increaser, since this transformation may well
/// take a bit of time if the iterations are large enough.
class CAxCryptAESWrap {
    static byte m_aoKeyWrapA[8];            ///< FIPS recommended constant value.

    byte *m_pWrap;                          ///< The Key Data (A + DEK).
    byte *m_pSalt;                          ///< Salt, xor'ed with KEK before wrap/unwrap.
    int m_nKeySize;                         ///< The key size we work in
    longlong m_nIter;                       ///< Custom number of iterations for work factor increase
public:
    /// \brief Constructor, define iter and salt-size params.
    CAxCryptAESWrap(longlong nIter = 6, int nKeySize = 16);
    /// \brief Init, define iterations and salt-size params.
    void Init(longlong nIter, int nKeySize = 16);
    ~CAxCryptAESWrap();
    /// \brief FIPS-wrap a key using the specified parameters
    void Wrap(const void *pWrappingKey, const void *pKeyToWrap, const void *pSalt);
    /// \brief Unwrap a FIPS-wrapped key using the specified parameters
    bool UnWrap(const void *pWrappingKey, const void *pWrappedKey, const void *pSalt);
    /// \brief The caller must know the size of the salt.
    byte *GetSalt();
    /// \brief Just get the key, obviously m_nKeySize long.
    byte *GetKey();
    /// \brief The result is by definition m_nKeySize + 8 bytes long.
    byte *GetWrap();
    /// \brief Get the size of the wrap
    size_t WrapSize();
    /// \brief Set the (unwrapped) key and salt
    void SetKeyAndSalt(const void *pKeyToWrap, const void *pSalt);
};
} // namespace axcl
#endif CAXCRYPTAES_H
/*
    @(#) $Id$

	Ax Crypt - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001 Svante Seleborg/Axon Data, All rights reserved.

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
	CAes.cpp						Special purpose wrapper-class for AES-primitives

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
                                    2002-08-11              Rel 1.2

*/
#include	"stdafx.h"
#include	"CAes.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CAes.cpp"

// Need to use C linkage specification. Alternatively compile as C++
extern "C" {
#include	"../AES/rijndael-alg-fst.h"
}
//
// 	Default constructor - just mark it as not ready.
//
CAes::CAes() {
	m_bStateOk = FALSE;
	m_pdwRoundKeys = NULL;
}
//
//	Destructor
//
CAes::~CAes() {
	if (m_pdwRoundKeys != NULL) delete m_pdwRoundKeys;
}

//
//	Construct and initialize in one step.
//
CAes::CAes(TKey *putKey, etMode eMode, etDirection eDirection, etKeyLength eKeyLength) {
	m_pdwRoundKeys = NULL;
	Init(putKey, eMode, eDirection, eKeyLength);
}
//
//	Initialize for encryption or decryption and key length.
//	Currently only 128 bits is supported.
//
//	No error return or exception from the constructor, but if there is an error,
//	block transformation will fail and return FALSE.
//
void
CAes::Init(TKey *putKey, etMode eMode, etDirection eDirection, etKeyLength eKeyLength) {
	if (m_pdwRoundKeys != NULL) {
		delete m_pdwRoundKeys;
		m_pdwRoundKeys = NULL;
	}
	m_bStateOk = FALSE;
	if (eKeyLength == eKey128Bits) {
		m_iNr = 10;							// 10 rounds for 128-bit encryption.
		m_pdwRoundKeys = new DWORD[4*(m_iNr+1)];
        ASSPTR(m_pdwRoundKeys);

		m_eDirection = eDirection;
		if (eDirection == eEncrypt) {
            ASSCHK(rijndaelKeySetupEnc((u32 *)m_pdwRoundKeys, (u8 *)putKey, 128) == m_iNr, _T("Internal configuration error in the Advanced Encryption Standard library."));
		} else if (eDirection == eDecrypt) {
            ASSCHK(rijndaelKeySetupDec((u32 *)m_pdwRoundKeys, (u8 *)putKey, 128) == m_iNr, _T("Internal configuration error in the Advanced Encryption Standard library."));
		} else return;
		ZeroMemory(&m_utIV, sizeof m_utIV);		// Default IV
	}
	if (eMode != eECB && eMode != eCBC) return;
	m_eMode = eMode;
	m_bStateOk = TRUE;
}

//
//	Transform (encrypt or decrypt) according to parameters set at construction.
//
//	return TRUE if all is ok - FALSE otherwise. Currently only parameter selection
//	fault will return FALSE, no further validation is done.
//
//	Supports:
//	Electronic Code Book (ECB) mode - i.e. independent block-by-block encryption/decryption
//	Cipher Block Chaining (CBC) mode - where each Message Block is first XOR:ed with the
//		previous encrypted block. The first block is encrypted with an Init Vector, default zero.
//		The last block is saved as new IV for subsequent calls.
//
//	The code makes use of the TBlock class to algorithm block entities directly.
//
BOOL
CAes::Xblock(TBlock *putSrc, TBlock *putDst, DWORD dwBlocks) {
	if (m_bStateOk) {
		if (m_eDirection == eEncrypt) {
			if (m_eMode == eECB) {
				while (dwBlocks--) {
					rijndaelEncrypt((u32 *)m_pdwRoundKeys, m_iNr, (u8 *)putSrc++, (u8 *)putDst++);
				}
			} else if (m_eMode == eCBC) {
				// We cannot do nifty pointer stuff to handle the chaining, since we need to
				// support overlapping (identical) Src and Dst. If you want to optimize, an
				// if here and below with a slight variation of the code will help, but it
				// simply does not feel necessary right now.
				while (dwBlocks--) {
					*putDst = *putSrc++;
					*putDst ^= m_utIV;
					rijndaelEncrypt((u32 *)m_pdwRoundKeys, m_iNr, (u8 *)putDst, (u8 *)putDst);
					CopyMemory(&m_utIV, putDst++, sizeof TBlock);
				}
			} else return FALSE;
			return TRUE;
		} else if (m_eDirection == eDecrypt) {
			if (m_eMode == eECB) {
				while (dwBlocks--) {
					rijndaelDecrypt((u32 *)m_pdwRoundKeys, m_iNr, (u8 *)putSrc++, (u8 *)putDst++);
				}
			} else if (m_eMode == eCBC) {
				// We cannot do nifty pointer stuff to handle the chaining, since we need to
				// support overlapping (identical) Src and Dst
				TBlock utPrevBlock;
				CopyMemory(&utPrevBlock, &m_utIV, sizeof TBlock);
				while (dwBlocks--) {
					CopyMemory(&m_utIV, putSrc, sizeof TBlock);
					rijndaelDecrypt((u32 *)m_pdwRoundKeys, m_iNr, (u8 *)putSrc++, (u8 *)putDst);
					*putDst++ ^= utPrevBlock;
					CopyMemory(&utPrevBlock, &m_utIV, sizeof TBlock);
				}
			} else return FALSE;
			return TRUE;
		}
	}
	return FALSE;
}

void
CAes::SetIV(TBlock *putIV) {
	CopyMemory(&m_utIV, putIV, sizeof m_utIV);
}
//
//	The value of the constant according to FIPS recommendations
//
BYTE CAesWrap::m_aoKeyWrapA[8] = {
	0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
};

CAesWrap::CAesWrap(int nIter, int nKeySize) {
    Init(nIter, nKeySize);
}

void CAesWrap::Init(int nIter, int nKeySize) {
    m_nIter = nIter;
    m_nKeySize = nKeySize;
    m_pSalt = new BYTE[m_nKeySize];
    ASSPTR(m_pSalt);

    m_pWrap = new BYTE[sizeof m_aoKeyWrapA + m_nKeySize];
    ASSPTR(m_pWrap);
}

CAesWrap::~CAesWrap() {
    if (m_pSalt != NULL) {
        ZeroMemory(m_pSalt, m_nKeySize);
        delete m_pSalt;
    }
    if (m_pWrap != NULL) {
        ZeroMemory(m_pWrap, sizeof m_aoKeyWrapA + m_nKeySize);
        delete m_pWrap;
    }
}
//
//	Wrap key with KEK using AES FIPS recommendations.
//
//	A Salt is added to the Key Encrypting Key before wrapping, according to the
//	ideas and thoughts presented in RSA Laboratories PKCS#5 v2.0. This prevents
//	attacks based on precomputing. The caller provdes the salt.
//
void
CAesWrap::Wrap(void *pWrappingKey, void *pKeyToWrap, void *pSalt) {
	// Init according to FIPS recommendation.
    CopyMemory(&m_pWrap[0], m_aoKeyWrapA, sizeof m_aoKeyWrapA);

    // Then copy the Data Encryption Key to KeyData
    CopyMemory(&m_pWrap[sizeof m_aoKeyWrapA], pKeyToWrap, m_nKeySize);
    // and then the salt
    CopyMemory(m_pSalt, pSalt, m_nKeySize);

    // Finally generate the Salted Key Wrapping Key by XOR-ing the given key with the salt.
	auto_ptr<BYTE> pSaltedWrappingKey(new BYTE[m_nKeySize]);	// Self-destructing
    ASSPTR(pSaltedWrappingKey.get());

    XorMemory(pSaltedWrappingKey.get(), pWrappingKey, m_pSalt, m_nKeySize);

    // Use AES in Electronic Code Book mode.
    CAes utAes;
    utAes.Init((TKey *)(BYTE *)(pSaltedWrappingKey.get()), CAes::eECB, CAes::eEncrypt, CAes::eKey128Bits);

    // Allocate the temporary B-block on the secured heap too.
    auto_ptr<TBlock> putB(new TBlock);    // Will call delete on destruction.
    ASSPTR(putB.get());

    // Just for claritys sake - the number of 64-bit blocks in a key.
    const int n = m_nKeySize / 8;

    // m_pWrap[0..7] contains the A (IV) of the Key Wrap algorithm,
    // the rest is 'Key Data'. We do the transform in-place.
    for (int j = 0; j < m_nIter; j++) {
        for (int i = 1; i <= n; i++) {
            // B = AESE(K, A | R[i])
            putB->Msb64() = *(QWORD *)&m_pWrap[0];
            putB->Lsb64() = *(QWORD *)&m_pWrap[i<<3];
            utAes.Xblock(putB.get(), putB.get());
            // A = MSB64(B) XOR t where t = (n * j) + i
            *(QWORD *)&m_pWrap[0] = putB->Msb64() ^ ((n * j) + i);
            // R[i] = LSB64(B)
            *(QWORD *)&m_pWrap[i<<3] = putB->Lsb64();
        }
    }
}

BOOL
CAesWrap::UnWrap(void *pWrappingKey, void *pWrappedKey, void *pSalt) {
    // Copy the wrapped data to class local storage
    CopyMemory(m_pWrap, pWrappedKey, sizeof m_aoKeyWrapA + m_nKeySize);

	// Generate the Salted KEK by XOR-ing the given key with the salt.
	auto_ptr<BYTE> pSaltedWrappingKey(new BYTE[m_nKeySize]);	// Self-destructing
    ASSPTR(pSaltedWrappingKey.get());

	XorMemory(pSaltedWrappingKey.get(), pWrappingKey, pSalt, m_nKeySize);

    // Use AES in Electronic Code Book mode.
    CAes utAes;
    utAes.Init((TKey *)(BYTE *)(pSaltedWrappingKey.get()), CAes::eECB, CAes::eDecrypt, CAes::eKey128Bits);

    // Allocate the temporary B-block on the secured heap too.
    auto_ptr<TBlock> putB(new TBlock);    // Will call delete on destruction.
    ASSPTR(putB.get());

    // Just for claritys sake
    const int n = m_nKeySize / 8;

    // m_pWrap[0..7] contains the A (IV) of the Key Wrap algorithm,
    // the rest is 'Wrapped Key Data'. We do the transform in-place.
    for (int j = m_nIter - 1; j >= 0; j--) {
        for (int i = n; i >= 1; i--) {
            // B = AESD(K, A XOR t | R[i]) where t = (n * j) + i
            putB->Msb64() = *(QWORD *)&m_pWrap[0] ^ ((n * j) + i);
            putB->Lsb64() = *(QWORD *)&m_pWrap[i<<3];
            utAes.Xblock(putB.get(), putB.get());
            // A = MSB64(B)
            *(QWORD *)&m_pWrap[0] = putB->Msb64();
            // R[i] = LSB64(B)
            *(QWORD *)&m_pWrap[i<<3] = putB->Lsb64();
        }
    }
    return memcmp(m_pWrap, m_aoKeyWrapA, sizeof m_aoKeyWrapA) == 0;
}

BYTE *
CAesWrap::GetSalt() {
    return m_pSalt;
}

BYTE *
CAesWrap::GetKey() {
    return &m_pWrap[sizeof m_aoKeyWrapA];
}

BYTE *
CAesWrap::GetWrap() {
    return m_pWrap;
}
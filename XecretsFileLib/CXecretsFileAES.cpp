/*! \file
	\brief CXecretsFileAES.cpp - An Xecrets File Classic special purpose AES-wrapper

	@(#) $Id$

	axcl - Common support library for Xecrets File Classic

	Copyright (C) 2005-2022 Svante Seleborg/Axantum Software AB, All rights reserved.

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

	Why is this framework released as GPL and not LGPL? See http://www.gnu.org/philosophy/why-not-lgpl.html

----
\verbatim
	YYYY-MM-DD              Reason
	2005-06-26              Initial (moved/restructured from Xecrets File Classic)
\endverbatim
*/
#include "stdafx.h"

#include <memory>
#include <memory.h>

#include "CXecretsFileAES.h"
#include "CXecretsFileLibMisc.h"

// Need to use C linkage specification. Alternatively compile as C++
extern "C" {
#include    "../AES/rijndael-alg-fst.h"
}

#include "Assert.h"
#define ASSERT_FILE "CXecretsFileAES.cpp"

namespace axcl {
	/// Default constructor - just mark it as not ready.
	CXecretsFileAES::CXecretsFileAES() {
		m_bStateOk = false;
		m_pdwRoundKeys = NULL;
	}
	/// delete allocated memory
	CXecretsFileAES::~CXecretsFileAES() {
		if (m_pdwRoundKeys != NULL) delete m_pdwRoundKeys;
	}

	/// Construct and initialize in one step.
	/// \param putKey Pointer to a byte-array representing the key. Length is defined by eKeyLength
	/// \param eMode The mode (eCBC or eECB)
	/// \param eDirection eEncrypt or eDecrypt
	/// \param eKeyLength eKey128Bits only supported now
	CXecretsFileAES::CXecretsFileAES(const TKey* putKey, etMode eMode, etDirection eDirection, etKeyLength eKeyLength) {
		m_pdwRoundKeys = NULL;
		Init(putKey, eMode, eDirection, eKeyLength);
	}
	//
	/// Construct and initialize in one step.
	/// No error return or exception from the constructor, but if there is an error,
	/// block transformation will fail and return false.
	/// \param putKey Pointer to a byte-array representing the key. Length is defined by eKeyLength
	/// \param eMode The mode (eCBC or eECB)
	/// \param eDirection eEncrypt or eDecrypt
	/// \param eKeyLength eKey128Bits only supported now
	void
		CXecretsFileAES::Init(const TKey* putKey, etMode eMode, etDirection eDirection, etKeyLength eKeyLength) {
		if (m_pdwRoundKeys != NULL) {
			delete m_pdwRoundKeys;
			m_pdwRoundKeys = NULL;
		}
		m_bStateOk = false;
		if (eKeyLength == eKey128Bits) {
			m_iNr = 10;                         // 10 rounds for 128-bit encryption.
			m_pdwRoundKeys = new uint32[4 * (m_iNr + 1)];
			ASSPTR(m_pdwRoundKeys);

			m_eDirection = eDirection;
			if (eDirection == eEncrypt) {
				ASSCHK(rijndaelKeySetupEnc((u32*)m_pdwRoundKeys, (u8*)putKey, 128) == m_iNr, _T("Internal configuration error in the Advanced Encryption Standard library."));
			}
			else if (eDirection == eDecrypt) {
				ASSCHK(rijndaelKeySetupDec((u32*)m_pdwRoundKeys, (u8*)putKey, 128) == m_iNr, _T("Internal configuration error in the Advanced Encryption Standard library."));
			}
			else return;
			memset(&m_utIV, 0, sizeof m_utIV);  // Default IV
		}
		if (eMode != eECB && eMode != eCBC) return;
		m_eMode = eMode;
		m_bStateOk = true;
	}

	/// \brief Transform (encrypt or decrypt) according to parameters set at construction.
	///
	/// Supports the following modes:
	///
	/// Electronic Code Book (ECB) mode - i.e. independent block-by-block encryption/decryption
	/// Cipher Block Chaining (CBC) mode - where each Message Block is first XOR:ed with the
	///     previous encrypted block. The first block is encrypted with an Init Vector, default zero.
	///     The last block is saved as new IV for subsequent calls.
	///
	/// The code makes use of the TBlock class to algorithm block entities directly.
	/// Currently only parameter selection fault will return false, no further validation is done.
	/// \param putSrc Pointer to one or more blocks of input
	/// \param putDst Pointer to one or more blocks of output
	/// \param nBlocks Number of blocks to transform.
	/// \return true if all is ok - false otherwise.
	bool
		CXecretsFileAES::Xblock(const TBlock* putSrc, TBlock* putDst, size_t nBlocks) {
		if (m_bStateOk) {
			if (m_eDirection == eEncrypt) {
				if (m_eMode == eECB) {
					while (nBlocks--) {
						rijndaelEncrypt((u32*)m_pdwRoundKeys, m_iNr, (u8*)putSrc++, (u8*)putDst++);
					}
				}
				else if (m_eMode == eCBC) {
					// We cannot do nifty pointer stuff to handle the chaining, since we need to
					// support overlapping (identical) Src and Dst. If you want to optimize, an
					// if here and below with a slight variation of the code will help, but it
					// simply does not feel necessary right now.
					while (nBlocks--) {
						*putDst = *putSrc++;
						*putDst ^= m_utIV;
						rijndaelEncrypt((u32*)m_pdwRoundKeys, m_iNr, (u8*)putDst, (u8*)putDst);
						memcpy(&m_utIV, putDst++, sizeof TBlock);
					}
				}
				else return false;
				return true;
			}
			else if (m_eDirection == eDecrypt) {
				if (m_eMode == eECB) {
					while (nBlocks--) {
						rijndaelDecrypt((u32*)m_pdwRoundKeys, m_iNr, (u8*)putSrc++, (u8*)putDst++);
					}
				}
				else if (m_eMode == eCBC) {
					// We cannot do nifty pointer stuff to handle the chaining, since we need to
					// support overlapping (identical) Src and Dst
					TBlock utPrevBlock;
					memcpy(&utPrevBlock, &m_utIV, sizeof TBlock);
					while (nBlocks--) {
						memcpy(&m_utIV, putSrc, sizeof TBlock);
						rijndaelDecrypt((u32*)m_pdwRoundKeys, m_iNr, (u8*)putSrc++, (u8*)putDst);
						*putDst++ ^= utPrevBlock;
						memcpy(&utPrevBlock, &m_utIV, sizeof TBlock);
					}
				}
				else return false;
				return true;
			}
		}
		return false;
	}

	/// Set the initial IV
	/// \param putIV Pointer to an IV
	void
		CXecretsFileAES::SetIV(const TBlock* putIV) {
		memcpy(&m_utIV, putIV, sizeof m_utIV);
	}

	CXecretsFileAESSubKey::CXecretsFileAESSubKey() {
		m_pSubKey = new TKey;
		ASSPTR(m_pSubKey);
	}

	/// Free allocated memory
	CXecretsFileAESSubKey::~CXecretsFileAESSubKey() {
		delete m_pSubKey;
	}

	/// Generate a sub-key given a master key. We do this by encrypting a small integer
	/// constant with the master key.
	/// This currently only supports 128-bit keys (a block is the size of a key...)
	/// \param pMasterKey The master key to use
	/// \param eSubKey The sub-key to generate. The enum value is used as an int and is encrypted to form the sub-key.
	/// \return A reference to self.
	CXecretsFileAESSubKey&
		CXecretsFileAESSubKey::Set(TKey* pMasterKey, etSubKey eSubKey) {
		TBlock utSubKeyData(eSubKey);
		CXecretsFileAES utCAesCtx(pMasterKey, CXecretsFileAES::eECB, CXecretsFileAES::eEncrypt);

		// We know that a TBlock and a TKey is of the same size... Change here if this
		// changes, or you want to write solid code...
		utCAesCtx.Xblock(&utSubKeyData, (TBlock*)m_pSubKey);

		return *this;
	}

	TKey*
		CXecretsFileAESSubKey::Get() {
		return m_pSubKey;
	}

	/// \brief  The value of the constant according to FIPS recommendations
	axcl::byte CXecretsFileAESWrap::m_aoKeyWrapA[8] = {
		0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
	};

	/// Construct a wrapping object with the appropriate parameters
	/// \param nIter The number of iterations - increase for work-factor increase
	/// \param nKeySize The key-size in bytes, i.e. 16 for 128-bit keys
	CXecretsFileAESWrap::CXecretsFileAESWrap(longlong nIter, int nKeySize) {
		m_pSalt = NULL;
		m_pWrap = NULL;
		Init(nIter, nKeySize);
	}

	/// Initialize a wrapping object with the appropriate parameters
	/// \param nIter The number of iterations - increase for work-factor increase
	/// \param nKeySize The key-size in bytes, i.e. 16 for 128-bit keys
	void CXecretsFileAESWrap::Init(longlong nIter, int nKeySize) {
		m_nIter = nIter;
		m_nKeySize = nKeySize;

		delete[] m_pSalt;
		m_pSalt = new byte[m_nKeySize];
		ASSPTR(m_pSalt);

		delete[] m_pWrap;
		m_pWrap = new byte[sizeof m_aoKeyWrapA + m_nKeySize];
		ASSPTR(m_pWrap);
	}

	/// Free and clear allocated memory
	CXecretsFileAESWrap::~CXecretsFileAESWrap() {
		if (m_pSalt != NULL) {
			memset(m_pSalt, 0, m_nKeySize);
			delete[] m_pSalt;
		}
		if (m_pWrap != NULL) {
			memset(m_pWrap, 0, sizeof m_aoKeyWrapA + m_nKeySize);
			delete[] m_pWrap;
		}
	}
	/// \brief Wrap key with KEK using AES FIPS recommendations.
	///
	/// A Salt is added to the Key Encrypting Key before wrapping, according to the
	/// ideas and thoughts presented in RSA Laboratories PKCS#5 v2.0. This prevents
	/// attacks based on precomputing. The caller provdes the salt.
	/// \param pWrappingKey A key (of the appropriate size) to use for the wrapping
	/// \param pKeyToWrap A key (of the same size as the wrapping key) to wrap
	/// \param pSalt A random non-secret salt (of the same size as the key)
	void
		CXecretsFileAESWrap::Wrap(const void* pWrappingKey, const void* pKeyToWrap, const void* pSalt) {
		SetKeyAndSalt(pKeyToWrap, pSalt);

		// Finally generate the Salted Key Wrapping Key by XOR-ing the given key with the salt.
		std::auto_ptr<byte> pSaltedWrappingKey(new byte[m_nKeySize]);    // Self-destructing
		ASSPTR(pSaltedWrappingKey.get());

		XorMemory(pSaltedWrappingKey.get(), pWrappingKey, m_pSalt, m_nKeySize);

		// Use AES in Electronic Code Book mode.
		CXecretsFileAES utAes;
		utAes.Init((TKey*)(byte*)(pSaltedWrappingKey.get()), CXecretsFileAES::eECB, CXecretsFileAES::eEncrypt, CXecretsFileAES::eKey128Bits);

		// Allocate the temporary B-block on the secured heap too.
		std::auto_ptr<TBlock> putB(new TBlock);    // Will call delete on destruction.
		ASSPTR(putB.get());

		// Just for claritys sake - the number of 64-bit blocks in a key.
		const int n = m_nKeySize / 8;

		// m_pWrap[0..7] contains the A (IV) of the Key Wrap algorithm,
		// the rest is 'Key Data'. We do the transform in-place.
		for (int j = 0; j < m_nIter; j++) {
			for (int i = 1; i <= n; i++) {
				// B = AESE(K, A | R[i])
				putB->Msb64() = *(uint64*)&m_pWrap[0];
				putB->Lsb64() = *(uint64*)&m_pWrap[i << 3];
				utAes.Xblock(putB.get(), putB.get());
				// A = MSB64(B) XOR t where t = (n * j) + i
				*(uint64*)&m_pWrap[0] = putB->Msb64() ^ ((n * j) + i);
				// R[i] = LSB64(B)
				*(uint64*)&m_pWrap[i << 3] = putB->Lsb64();
			}
		}
	}

	/// Unwrap a FIPS-wrapped key
	/// \param pWrappingKey Pointer to a byte-array representing the key used to wrap
	/// \param pWrappedKey Pointer to a byte-array representing the key that is wrapped
	/// \param pSalt Pointer to the salt used
	/// \return true if all ok
	bool
		CXecretsFileAESWrap::UnWrap(const void* pWrappingKey, const void* pWrappedKey, const void* pSalt) {
		// Copy the wrapped data to class local storage
		memcpy(m_pWrap, pWrappedKey, sizeof m_aoKeyWrapA + m_nKeySize);

		// Generate the Salted KEK by XOR-ing the given key with the salt.
		std::auto_ptr<byte> pSaltedWrappingKey(new byte[m_nKeySize]);    // Self-destructing
		ASSPTR(pSaltedWrappingKey.get());

		XorMemory(pSaltedWrappingKey.get(), pWrappingKey, pSalt, m_nKeySize);

		// Use AES in Electronic Code Book mode.
		CXecretsFileAES utAes;
		utAes.Init((TKey*)(byte*)(pSaltedWrappingKey.get()), CXecretsFileAES::eECB, CXecretsFileAES::eDecrypt, CXecretsFileAES::eKey128Bits);

		// Allocate the temporary B-block on the secured heap too.
		std::auto_ptr<TBlock> putB(new TBlock);    // Will call delete on destruction.
		ASSPTR(putB.get());

		// Just for claritys sake
		const int n = m_nKeySize / 8;

		// m_pWrap[0..7] contains the A (IV) of the Key Wrap algorithm,
		// the rest is 'Wrapped Key Data'. We do the transform in-place.
		for (longlong j = m_nIter - 1; j >= 0; j--) {
			for (int i = n; i >= 1; i--) {
				// B = AESD(K, A XOR t | R[i]) where t = (n * j) + i
				putB->Msb64() = *(uint64*)&m_pWrap[0] ^ ((n * j) + i);
				putB->Lsb64() = *(uint64*)&m_pWrap[i << 3];
				utAes.Xblock(putB.get(), putB.get());
				// A = MSB64(B)
				*(uint64*)&m_pWrap[0] = putB->Msb64();
				// R[i] = LSB64(B)
				*(uint64*)&m_pWrap[i << 3] = putB->Lsb64();
			}
		}
		return memcmp(m_pWrap, m_aoKeyWrapA, sizeof m_aoKeyWrapA) == 0;
	}

	/// Do what the name says.
	/// \return The pointer to the salt. The size is set in the constructor or Init()-call.
	byte*
		CXecretsFileAESWrap::GetSalt() {
		return m_pSalt;
	}

	/// Get the actual key location. This is only relevant after unwrapping.
	/// \return A pointer to a byte array of the size given on init.
	byte*
		CXecretsFileAESWrap::GetKey() {
		return &m_pWrap[sizeof m_aoKeyWrapA];
	}

	/// Get the entire wrapped block. This is only relevant after wrapping.
	/// \return a A pointer to a byte array, size of the wrap constant plus the given size of the key
	byte*
		CXecretsFileAESWrap::GetWrap() {
		return m_pWrap;
	}

	size_t
		CXecretsFileAESWrap::WrapSize() {
		return m_nKeySize + 8;
	}

	void
		CXecretsFileAESWrap::SetKeyAndSalt(const void* pKeyToWrap, const void* pSalt) {
		// Init according to FIPS recommendation.
		memcpy(&m_pWrap[0], m_aoKeyWrapA, sizeof m_aoKeyWrapA);

		// Then copy the Data Encryption Key to KeyData
		memcpy(&m_pWrap[sizeof m_aoKeyWrapA], pKeyToWrap, m_nKeySize);
		// and then the salt
		memcpy(m_pSalt, pSalt, m_nKeySize);
	}
}
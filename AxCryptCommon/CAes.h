#ifndef	_CAES
#define	_CAES
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
	CAes.h							Special purpose wrapper-class for AES-primitives.

	E-mail							YYYY-MM-DD				Reason
	software@axantum.com 			2001					Initial
                                    2002-08-04              Rel 1.2 (CAesWrap added)

*/
//#include	"Types.h"
//
//	Simple wrapper class for the AES-code.
//
//	A major reason to do our own wrapper instead of using existing code is that
//	we need to ensure that keys and round keys are kept in dynamically allocated
//	storage that we know is safe. This requires that the 'new' and 'delete' operators
//	are redefined to guarantuee the safety of the data in whatever way is deemed
//	appropriate. In Ax Crypt this is done by way of a memory mapped file as the heap.
//
//	The Init Vector is never secret - so we keep it in regular memory.
//
//	To get full control we only use the low-level algoritm parts.
//
//	This class is not a complete API - it only implements exactly the modes
//	needed by Ax Crypt.
//
//	Please note that padding must be done external to this code - we only
//	handle whole blocks here.
//
class CAes {
public:
	enum etDirection {eEncrypt, eDecrypt};
	enum etMode {eECB, eCBC};
	enum etKeyLength {eKey128Bits, eKey192Bits, eKey256Bits};

	CAes();
	~CAes();
	CAes(TKey *putKey, etMode eMode, etDirection eDirection, etKeyLength eKeyLength = eKey128Bits);
	void Init(TKey *putKey, etMode eMode, etDirection eDirection, etKeyLength eKeyLength = eKey128Bits);
	void SetIV(TBlock *putIV);
	BOOL Xblock(TBlock *putSrc, TBlock *putDst, DWORD dwBlocks = 1);
private:
	// Use pointers - easier to upgrade to variable key lengths
	DWORD *m_pdwRoundKeys;			// 4*10 = 40x32 bits. 128-bit keys use 10-rounds.
	TBlock m_utIV;					// Init Vector - updated in CBC-mode
	int m_iNr;						// Number of rounds
	BOOL m_bStateOk;				// TRUE if init ok.
	etDirection m_eDirection;		// Keep track of tranformation direction...
	enum etMode m_eMode;			// ...and mode...
	enum etKeyKength m_eKeyLength;	// ...and key length
};
//
//  Implement the FIPS-recommended Key Wrapping algorithm with AES.
//  This is a self-checking iterative transformation, that can also be
//  used as a work-factor increaser, since this transformation may well
//  take a bit of time if the iterations are large enough.
//
class CAesWrap {
    static BYTE m_aoKeyWrapA[8];        // FIPS recommended constant value.

    BYTE *m_pWrap;                      // The Key Data (A + DEK).
	BYTE *m_pSalt; 					    // Salt, xor'ed with KEK before wrap/unwrap.
    int m_nKeySize;
    int m_nIter;      				    // Custom number of iterations for work factor increase
public:
    CAesWrap(int nIter = 6, int nKeySize = 16);// Constructor, define iter and salt-size params.
    void Init(int nIter, int nKeySize = 16);
    ~CAesWrap();
    void Wrap(void *pWrappingKey, void *pKeyToWrap, void *pSalt);
    BOOL UnWrap(void *pWrappingKey, void *pWrappedKey, void *pSalt);
    BYTE *GetSalt();                    // The caller must know the size of the salt.
    BYTE *GetKey();                     // Just get the key, obviously m_nKeySize long.
    BYTE *GetWrap();                    // This is by definition m_nKeySize + 8 long.
};
#endif	_CAES
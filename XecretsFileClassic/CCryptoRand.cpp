/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2023 Svante Seleborg/Axon Data, All rights reserved.

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
----
	CCryptoRand.cpp					Entropy pool and random number generator (FIPS 186-2).
									Reference:
									http://csrc.nist.gov/publications/fips/fips186-2/fips186-2.pdf

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
//
//	A 128-bit random number is calculated using SHA-1 according to FIPS 186-2.
//
//	We use the algorithm in FIPS 186-2 such that the seed-key, XKEY, is actually
//	a fixed public value. If nothing else is done - this algorithm thus 'degenerates'
//	into a nonce-generator, still useful for Initialization Vectors but not for
//	Data Encrypting Keys.
//
//	To generate a Data Encrypting Key, an additional secret value called 'User Input'
//	or XSEED is needed. This should be based on the user-specified Key Encrypting Key
//	as that is the only really secret value we have.
//
//	To generate 'secure' random numbers, and not just nonces, you MUST give a new SEED
//	before every such generation.
//
//	The code also adds in a time stamp to ensure that a re-run under similar situations
//	still will generate unique Data Encrypting Keys and nonces. The time stamp comes both
//	from the tick-counter and from Time of Day clock.
//
//	TODO:	Add some 'true' randomness into the 'entropy pool' m_putXSeed, probably by having
//			a timer pick something up, such as mouse pointer position change or whatever.
//

#include	"StdAfx.h"
#include	"CCryptoRand.h"

#include    "../AxWinLib/AxAssert.h"
#define     AXLIB_ASSERT_FILE "CCryptoRand.cpp"
//
// This is not a secret. We use 160-bit XKEY/XVAL/XSEED values.
// It could have been zero, but this feels better.
//
DWORD CCryptoRand::m_dwInitKey[5] = {
	0xc3de9724, 0x68a081ab, 0x4d22d5e5, 0x16515526, 0x66194031
};

CCryptoRand::CCryptoRand() {
	// Must allocate here, not as members to ensure that it winds up in the
	// secured heap.
	m_putXKey = new THash((BYTE*)&m_dwInitKey, sizeof THash);
	ASSPTR(m_putXKey);

	m_putXSeed = new THash;
	ASSPTR(m_putXSeed);

	m_putContext = new SHA1_CTX;
	ASSPTR(m_putContext);
}

CCryptoRand::~CCryptoRand() {
	delete m_putContext;
	delete m_putXSeed;
	delete m_putXKey;
}

//
//	Generating random data is *hard*... We have an 'entropy pool' which
//	is gathering data, based on mouse movements and other things. If
//	these fail, we also add in the user-supplied key. The strategy being
//	that even if it is not random, it *is* secret from the attacker point
//	of view, by definition. The problem which may be hard to predict the
//	effect of is of course some kind of inter-dependency between key
//	encrypting keys and data encrypting keys.
//	Just for forms sake, we also here (but not to the entropy pool)
//	add in some time, which is the usual, not-so-good-idea. Better ideas
//	are appreciated as comments to me!
//
CCryptoRand&
CCryptoRand::Seed(void* pvXSeed, int iLen) {
	SHA1Init(m_putContext);

	// Hash in the user supplied (secret) data.
	SHA1Update(m_putContext, (BYTE*)pvXSeed, iLen);

	// Hash in tick count from system
	DWORD dwTickCount = GetTickCount();
	SHA1Update(m_putContext, (BYTE*)&dwTickCount, sizeof dwTickCount);

	// Also hash in the sytem time.
	SYSTEMTIME sdtSystemTime;
	GetSystemTime(&sdtSystemTime);
	SHA1Update(m_putContext, (BYTE*)&sdtSystemTime, sizeof sdtSystemTime);

	// Add 128 bits of entropy from the entropy pool
	BYTE aoEntropy[16];
	pgEntropyPool->Read(aoEntropy, sizeof aoEntropy);
	SHA1Update(m_putContext, aoEntropy, sizeof aoEntropy);

	// Re-hash the old seed to get full dependency of all previous.
	SHA1Update(m_putContext, (BYTE*)m_putXSeed, sizeof * m_putXSeed);

	// Get the final hash to the seed.
	SHA1Final((BYTE*)m_putXSeed, m_putContext);
	return *this;
}
//
//	Generate a pseudo random (dwLen*8)-bit number according to FIPS 186-2.
//
//	Please note that without a call to the Seed function, the numbers generated are
//	not cryptographically pseudo random, only pseudo random and thus only useful for nonces.
//
//	Also note that if generating cryptographically secure psuedo random numbers, the
//	buffer should be placed in secure memory, not the stack or regular data segment!
//
//	Fill a buffer with 'random' data according to the algorithm. No special care is taken
//	for padding, we just simply discard the trailing bits.
//
void
CCryptoRand::RandomFill(void* vpBuf, DWORD dwLen) {
	THash utXVal;
	while (dwLen) {
		SHA1Init(m_putContext);

		utXVal = *m_putXKey + *m_putXSeed;			// XVAL = (XKEY + XSEED) mod 2**160

		SHA1Transform(m_putContext, (BYTE*)&utXVal);

		// Update XKey: XKEY = (1 + XKEY + Xj) mod 2**160
		*m_putXKey = *m_putXKey + THash(1) + *(THash*)m_putContext->state;

		CopyMemory(vpBuf, m_putContext->state, min(sizeof THash, dwLen));

		// Update buffer pointer, decrease length.
		vpBuf = (BYTE*)vpBuf + sizeof THash;
		dwLen -= min(sizeof THash, dwLen);
	}
}
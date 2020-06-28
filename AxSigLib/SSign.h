#ifndef AXSIGLIB_SECDSA_SSIGN_H
#define AXSIGLIB_SECDSA_SSIGN_H
/*! \file
	\brief AxSigLib - Short Elliptic Curve Digital Signature Algorithm et. al.

	@(#) $Id$

	The SECDSA Signer

	Copyright (C) 2001-2020 Svante Seleborg/Axantum Software AB, All rights reserved.

	The author may be reached at mailto:axcrypt@axondata.se and http://axcrypt.sourceforge.net
---
*/

#include "secdsa.h"

template <class SSS> class SHORTSIGN : public SSS::Signer, public Canonicalize {
public:
	SHORTSIGN() : SSS::Signer() {}
	SHORTSIGN(BufferedTransformation& bt) : SSS::Signer(bt) {}

	/// \brief Calculate actual signature length
	/// There is a potential problem here... If this is used inside the class for purposes
	/// of memory allocation, we're in trouble as it's virtual. Not sure if it really should
	/// be, but that's the way it is - and it does appear that currently it's not used
	/// from base classes for that purpose. Presumably MaxSignatureLength() serves that
	/// purpose, but the documentation for the library somewhat brief. (Sarcasm intended).
	virtual unsigned int SignatureLength() const {
		return ((SSS::Rbits() - 1) / 8) + 1
			+ GetSignatureAlgorithm().SLen(this->GetAbstractGroupParameters());
	}

	//! maximum signature length produced for a given length of recoverable message part
	virtual unsigned int MaxSignatureLength(unsigned int recoverablePartLength = 0) const {
		return max(SignatureLength(), SSS::Signer::MaxSignatureLength(recoverablePartLength));
	}

	unsigned int SignAndRestart(RandomNumberGenerator& rng, PK_MessageAccumulator& messageAccumulator, byte* signature, bool restart) const {
		// Allocate a temp buffer for the inner signature
		SecByteBlock largesig(SSS::Signer::SignatureLength());

		// Do the inner signature, the siglen returned is our own siglen since SignatureLength() is virtual...
		unsigned int siglen = SSS::Signer::SignAndRestart(rng, messageAccumulator, largesig, restart);

		unsigned int rLen = GetSignatureAlgorithm().RLen(this->GetAbstractGroupParameters());
		unsigned int sLen = GetSignatureAlgorithm().SLen(this->GetAbstractGroupParameters());

		// Unpack r and s again into Integer's.
		Integer r, s;
		r.Decode(largesig, rLen);
		s.Decode(largesig + rLen, sLen);

		// Now prepare a compact representation, where we shorten r to RBITS, and the shift it
		// up just above r in one compact Integer.

		Integer sr = r;

		sr += s << SSS::Rbits();
		sr.Encode(signature, SignatureLength());

		//this->GetAbstractGroupParameters().GetGroupOrder().BitCount()
		//memcpy(signature, largesig, siglen);
		return siglen;
	};
};

#endif

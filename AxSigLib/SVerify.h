#ifndef AXSIGLIB_SECDSA_SVERIFY_H
#define AXSIGLIB_SECDSA_SVERIFY_H
/*! \file
	\brief AxSigLib - Short Elliptic Curve Digital Signature Algorithm et. al.

	@(#) $Id$

	The SECDSA Verifier

	Copyright (C) 2001-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

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
---
*/

#include "secdsa.h"

/// \brief Verify an optimized short signature.
/// First we unpack r and s, then pass it on to the regular verifier.
template <class SSS> class SHORTVERIFY : public SSS::Verifier, public Canonicalize {
public:
	/// \brief Construct a Verifier object by passing on to the base class
	/// \param priv A Signer to base the Verifier on.
	SHORTVERIFY(const typename SSS::Signer& priv) : SSS::Verifier(priv) {
	}

	/// \brief Construct from a BT with with a hexdecoder or similar
	SHORTVERIFY(BufferedTransformation& bt) : SSS::Verifier(bt) {
	}

	/// \brief Default constructor. Initialize with something like AccessKey().BERDecode(....)
	SHORTVERIFY() : SSS::Verifier() {
	}

	/// \brief Calculate actual signature length
	/// There is a potential problem here... If this is used inside the class for purposes
	/// of memory allocation, we're in trouble as it's virtual. Not sure if it really should
	/// be, but that's the way it is - and it does appear that currently it's not used
	/// from base classes for that purpose. Presumably MaxSignatureLength() serves that
	/// purpose, but the documentation for the library somewhat brief. (Sarcasm intended).
	virtual size_t SignatureLength() const {
		return ((SSS::Rbits() - 1) / 8) + 1
			+ GetSignatureAlgorithm().SLen(this->GetAbstractGroupParameters());
	}

	//! maximum signature length produced for a given length of recoverable message part
	virtual size_t MaxSignatureLength(size_t recoverablePartLength = 0) const {
		return max(SignatureLength(), SSS::Verifier::MaxSignatureLength(recoverablePartLength));
	}

	void InputSignature(PK_MessageAccumulator& messageAccumulator, const byte* signature, size_t signatureLength) const {
		Integer sr;
		sr.Decode(signature, SignatureLength());

		Integer s, r;
		s = sr >> SSS::Rbits();
		r = sr % Integer().Power2(SSS::Rbits());

		// Allocate a temp buffer for the inner signature
		SecByteBlock largesig(SSS::Verifier::SignatureLength());

		// Pack r and s again into a large signature block r followed by s
		size_t rLen = GetSignatureAlgorithm().RLen(this->GetAbstractGroupParameters());
		size_t sLen = GetSignatureAlgorithm().SLen(this->GetAbstractGroupParameters());
		r.Encode(largesig, rLen);
		s.Encode(largesig + rLen, sLen);

		// Do the inner input of the signature
		SSS::Verifier::InputSignature(messageAccumulator, largesig, largesig.size());
	}
};

#endif
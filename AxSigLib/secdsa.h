#ifndef AXSIGLIB_SECDSA_H
#define AXSIGLIB_SECDSA_H
/*! \file
	\brief AxSigLib - Short Elliptic Curve Digital Signature Algorithm et. al.

	@(#) $Id$

	Base class for SECDSA Signers and Verifiers

	Copyright (C) 2001-2022 Svante Seleborg/Axantum Software AB, All rights reserved.

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
---
*/

#include <assert.h>
#include "cryptlib.h"
#include "eccrypto.h"

USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)

/// \brief SECDSA algorithm
/// Produce a shortened EC DSA-algorithm, where the resulting 'r' is guaranteed to fit into
/// RBITS bits.
template <class EC, class H, unsigned int RBITS>
class DL_Algorithm_SECDSA : public DL_Algorithm_ECDSA<EC> {
public:
	/// \brief Hash to Integers with the same hash that's used for the algorithm
	/// Create a shortened hash, to the bit, and represent it as an integer. The
	/// intention is to get the RBITS most significant bits of the full hash
	/// when treated as a byte-oriented big-endian large Integer. This may in fact
	/// not be the case, since it was too time consuming to figure out in detail what
	/// really happens in the Crypto++ library, but it would appear to be so anyway.
	/// If this ever needs to be independenty implemented or implemented in a different-
	/// endian architeture this might make a difference for interoperability.
	/// \param i1 The first Integer to hash
	/// \param i2 The second Integer to hash
	/// \return An Integer representing RBITS hash of the provided Integers
	Integer ShortHash2Integer(const Integer& i1, const Integer& i2) const {
		auto_ptr<byte> bi1(new byte[i1.MinEncodedSize()]);
		auto_ptr<byte> bi2(new byte[i2.MinEncodedSize()]);

		// Get the encoding of the Integer as a bigendian byte array
		i1.Encode(bi1.get(), i1.MinEncodedSize());
		i2.Encode(bi2.get(), i2.MinEncodedSize());

		H Hash;
		Hash.Update(bi1.get(), i1.MinEncodedSize());
		Hash.Update(bi2.get(), i2.MinEncodedSize());

		// Get the topmost bytes necessary to contain RBITS
		auto_ptr<byte> bh(new byte[(RBITS - 1) / 8 + 1]);
		Hash.TruncatedFinal(bh.get(), (RBITS - 1) / 8 + 1);

		// Decode the hash and interpret as an Integer, h
		Integer h(bh.get(), (RBITS - 1) / 8 + 1);

		// Remove the last few bits, if any.
		h >>= 8 - RBITS % 8 > 7 ? 0 : 8 - RBITS % 8;

		return h;
	}

	static const char* StaticAlgorithmName() { return "SECDSA"; }

	/// \param r kG in Zheng and Imai notation
	/// \param e hash(m)
	void Sign(const DL_GroupParameters<typename EC::Point>& params, const Integer& x, const Integer& k, const Integer& e, Integer& r, Integer& s) const {
		// Normal EC DSS according to Zheng and Imai
		// r = (kG) mod q
		// s = ((hash(m) + xr)/k) mod q
		/*
		// The original DL_Algorithm_GDSA Sign() from Crypto++

		const Integer &q = params.GetSubgroupOrder();
		r %= q;
		Integer kInv = k.InverseMod(q);
		s = (kInv * (x*r + e)) % q;
		assert(!!r && !!s);
		*/

		// Shortened EC DSA according to Zheng and Imai
		// r = hash(kG, m) [kG is calucated as ExponentiateBase(k)]
		// s = k * inv(r + x) mod q
		// x is private key
		const Integer& q = params.GetSubgroupOrder();
		r = ShortHash2Integer(r, e);
		s = (k * Integer(r + x).InverseMod(q)) % q;
		assert(!!r && !!s);
	}

	/// \param e = hash(m)
	bool Verify(const DL_GroupParameters<typename EC::Point>& params, const DL_PublicKey<typename EC::Point>& publicKey, const Integer& e, const Integer& r, const Integer& s) const {
		// Normal EC DSS according to Zheng and Imai
		// s' = (1/s) mod q
		// K = s'(hash(m)G + rPa)
		// assert K mod q == r
		/*
		// The original DL_Algorithm_GDSA Verify() from Crypto++
		Integer w = s.InverseMod(q);
		Integer u1 = (e * w) % q;
		Integer u2 = (r * w) % q;
		// verify r == (g^u1 * y^u2 mod p) mod q
		return r == params.ConvertElementToInteger(publicKey.CascadeExponentiateBaseAndPublicElement(u1, u2)) % q;
		*/

		// Shortened EC DSA according to Zheng and Imai
		// Base is G, Public key is Pa
		// K = s * ( rG + Pa )
		// assert hash(K, m) == r

		const Integer& q = params.GetSubgroupOrder();
		// Sanity check
		if (r >= q || r < 1 || s >= q || s < 1) {
			return false;
		}

		Integer u1 = (r * s) % q;
		Integer u2 = (1 * s) % q;
		Integer K = params.ConvertElementToInteger(publicKey.CascadeExponentiateBaseAndPublicElement(u1, u2)) % q;
		K = ShortHash2Integer(K, e);
		return K == r;
	}
};

template <class EC, class H, unsigned int RBITS>
class SECDSA : public DL_SS<DL_Keys_ECDSA<EC>, DL_Algorithm_SECDSA<EC, H, RBITS>, DL_SignatureMessageEncodingMethod_DSA, H> {
public:
	//typedef DL_SS<DL_Keys_ECDSA<EC>, DL_Algorithm_SECDSA<EC, H, RBITS>, DL_SignatureMessageEncodingMethod_DSA, H>::Signer Signer;
	//typedef DL_SS<DL_Keys_ECDSA<EC>, DL_Algorithm_SECDSA<EC, H, RBITS>, DL_SignatureMessageEncodingMethod_DSA, H>::Verifier Verifier;
	static unsigned int Rbits() {
		return RBITS;
	}
};

/// \brief just a simple base class to add function for a common canonicalization method
class Canonicalize {
public:
	/// \brief lower-case and remove all but alphanum.
	/// You should probably ensure that setlocale(LC_CTYPE, "C") or it's equivalent is
	/// executed first. The isalnum() and tolower() functions may work differently. If
	/// you're thinking of running in a Unicode scenario, you need to translate to the
	/// equivalent of the "C" locale first to be interoperable - or modify this function
	/// to handle it.
	static string CanonicalizeMessage(const string& sMessage) {
		string sCanon;
		for (size_t i = 0; i < sMessage.length(); i++) {
			if (::isalnum(sMessage[i])) {
				sCanon.push_back(sMessage[i]);
			}
		}
		transform(sCanon.begin(), sCanon.end(), sCanon.begin(), tolower);
		return sCanon;
	}
};

#endif
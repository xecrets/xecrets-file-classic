#ifndef AXSIGLIB_BASEMENC_H
#define AXSIGLIB_BASEMENC_H
/*! \file
	\brief AxSigLib - Short Elliptic Curve Digital Signature Algorithm et. al.

	@(#) $Id$

	Decode BaseM strings. These are based on the encoding vectors such as (for Base34):

	static const byte s_vecUpper[] = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789";
	static const byte s_vecLower[] = "abcdefghijklmnpqrstuvwxyz123456789";

	Copyright (C) 2005-2023 Svante Seleborg/Axantum Software AB, All rights reserved.

	The author may be reached at mailto:support@axantum.com and http://www.axantum.com
----
*/

#include "BaseM.h"

//! base m encoder, where m <= numer of printable characters.
/// We also need to know the bit-precision in this case, since it's not possible to do a
/// continous streaming and we want to be as efficient as is possible.
class BaseM_Encoder : public BaseN_Encoder {
public:
	BaseM_Encoder(BufferedTransformation* attachment = NULL) : BaseN_Encoder(attachment) {}

	BaseM_Encoder(const byte* alphabet, int anybase, int bits, BufferedTransformation* attachment = NULL, int padding = -1) {
		Detach(attachment);
		IsolatedInitialize(MakeParameters(Name::EncodingLookupArray(), alphabet)
			(Name::AnyBase(), anybase)
			(Name::BitPrecision(), bits)
			(Name::Pad(), padding != -1)
			(Name::PaddingByte(), byte(padding)));
	}

	void IsolatedInitialize(const NameValuePairs& parameters);
	unsigned int Put2(const byte* begin, unsigned int length, int messageEnd, bool blocking);

private:
	const byte* m_alphabet;
	int m_padding, m_base, m_bits;
	SecByteBlock m_buffer;
};

void BaseM_Encoder::IsolatedInitialize(const NameValuePairs& parameters) {
	parameters.GetRequiredParameter("BaseM_Encoder", Name::EncodingLookupArray(), m_alphabet);

	parameters.GetRequiredIntParameter("BaseM_Encoder", Name::AnyBase(), m_base);
	parameters.GetRequiredIntParameter("BaseM_Encoder", Name::BitPrecision(), m_bits);
	if (m_base <= 0 || m_base >= 256) {
		throw InvalidArgument("BaseM_Encoder: Invalid base");
	}

	byte padding;
	bool pad;
	if (parameters.GetValue(Name::PaddingByte(), padding)) {
		pad = parameters.GetValueWithDefault(Name::Pad(), true);
	}
	else {
		pad = false;
	}

	m_padding = pad ? padding : -1;
}

// We need to buffer all of it before starting.
unsigned int BaseM_Encoder::Put2(const byte* begin, unsigned int length, int messageEnd, bool blocking) {
	SecByteBlock outBuf;
	size_t lBufferSize = m_buffer.size();
	size_t lOutSize = 0;
	Integer v;

	FILTER_BEGIN;
	if (length) {
		m_buffer.Grow(lBufferSize + length);
		memcpy(m_buffer + lBufferSize, begin, length);
		lBufferSize += length;
	}

	// This I'm a bit unsure about.. Don't really like these kinds of tricky, tricky, macros.
	// Especially when there's absolutely no documentation...
	// Apparently this will generate a case statement, matching the switch generated by
	// FILTER_BEGIN, but I can't really see how this works.
	FILTER_OUTPUT(1, outBuf, 0, 0);

	// Only do anything at all, if we've received all of it.
	if (messageEnd) {
		// We want to ensure that all messages of the same length get encoded to the same
		// length, therefore we do a brute force calucation here of what is the reqired
		// room...

		if (m_bits) {
			// Base it on the caller indication of the number of bits to represent.
			v = Integer().Power2(m_bits);
			v = v - Integer(1);
		}
		else {
			// Create the largest integer possible, using outBuf as a temporary.
			// This may be a slightly inefficient representation, but it'll work
			outBuf.New(lBufferSize);
			memset(outBuf, 255, lBufferSize);
			v.Decode(outBuf, lBufferSize);
		}

		do {
			v /= m_base;
			lOutSize++;
		} while (v != 0);

		// Now lOutSize is the number of chars required to represent the largest possible value
		// in a buffer of the given size. This is good, because now we know exactly how long this
		// value is going to be, and will fill with high-order zeroes if necessary.

		// Allocate the necessary space.
		outBuf.New(lOutSize);

		// Represent the buffer as a large integer
		v.Decode(m_buffer, m_buffer.size());

		while (lOutSize--) {
			outBuf[lOutSize] = m_alphabet[v % m_base];
			v /= m_base;
		}
		FILTER_OUTPUT(2, outBuf, outBuf.size(), messageEnd);
	}
	FILTER_END_NO_MESSAGE_END;
}

#endif

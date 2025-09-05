#ifndef AXSIGLIB_BASE34ENC_H
#define AXSIGLIB_BASE34ENC_H
/*! \file
	\brief AxSigLib - Short Elliptic Curve Digital Signature Algorithm et. al.

	@(#) $Id$

	Encode Base34 strings. These are strings using A-N, P-Z, 1-9 as their digits,
	valued in that sequence, i.e. A is zero, 9 is thirty-two.

	Copyright (C) 2005-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

	The author may be reached at mailto:support@axantum.com and http://www.axantum.com
----
*/

#include "Base34.h"
#include "BaseMEnc.h"

//! Converts given data to base 34 (a-z, 1-9, excluding the letter 'o' and the digit '0').
class Base34Encoder : public SimpleProxyFilter {
public:
	Base34Encoder(BufferedTransformation* attachment = NULL, int bits = 0, bool uppercase = true, int outputGroupSize = 0, const std::string& separator = ":", const std::string& terminator = "")
		: SimpleProxyFilter(new BaseM_Encoder(new Grouper), attachment) {
		IsolatedInitialize(MakeParameters(Name::Uppercase(), uppercase)
			(Name::GroupSize(), outputGroupSize)
			(Name::BitPrecision(), bits)
			(Name::Separator(), ConstByteArrayParameter(separator)));
	}

	void IsolatedInitialize(const NameValuePairs& parameters);
};

void Base34Encoder::IsolatedInitialize(const NameValuePairs& parameters) {
	bool uppercase = parameters.GetValueWithDefault(Name::Uppercase(), true);
	m_filter->Initialize(CombinedNameValuePairs(
		parameters,
		MakeParameters(Name::EncodingLookupArray(), uppercase ? &s_vecUpper[0] : &s_vecLower[0], false)(Name::AnyBase(), 34, true)));
}

#endif

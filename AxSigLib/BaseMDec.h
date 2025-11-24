#ifndef AXSIGLIB_BASEMDEC_H
#define AXSIGLIB_BASEMDEC_H
/*! \file
	\brief AxSigLib - Short Elliptic Curve Digital Signature Algorithm et. al.

	@(#) $Id$

	Decode BaseM strings. These are based on the encoding vectors such as (for Base34):

	static const byte s_vecUpper[] = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789";
	static const byte s_vecLower[] = "abcdefghijklmnpqrstuvwxyz123456789";

	Copyright (C) 2005-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
*/

#include "BaseM.h"

//! base m decoder, where m is any number <= number of printable characters.
class BaseM_Decoder : public BaseN_Decoder {
public:
	BaseM_Decoder(const int* lookup, int anybase, int bits, BufferedTransformation* attachment = NULL) {
		Detach(attachment);
		IsolatedInitialize(MakeParameters(Name::DecodingLookupArray(), lookup)
			(Name::AnyBase(), anybase)
			(Name::BitPrecision(), bits));
	}

	void IsolatedInitialize(const NameValuePairs& parameters);
	size_t Put2(const byte* begin, size_t length, int messageEnd, bool blocking);

	static void InitializeDecodingLookupArray(int* lookup, const byte* alphabet, unsigned int base, bool caseInsensitive);

private:
	const int* m_lookup;
	int m_padding, m_base, m_bits;
	SecByteBlock m_buffer;
};

#endif
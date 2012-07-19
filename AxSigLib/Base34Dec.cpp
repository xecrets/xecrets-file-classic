/*! \file
    \brief AxSigLib - Short Elliptic Curve Digital Signature Algorithm et. al.

    @(#) $Id$

    Decode Base34 strings. These are strings using A-N, P-Z, 1-9 as their digits,
    valued in that sequence, i.e. A is zero, 9 is thirty-two.

    Copyright (C) 2005 Svante Seleborg/Axon Data, All rights reserved.

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
*/
#include "stdafx.h"
#include "Base34Dec.h"

void
Base34Decoder::IsolatedInitialize(const NameValuePairs &parameters) {
    BaseM_Decoder::Initialize(CombinedNameValuePairs(
        parameters,
        MakeParameters(Name::DecodingLookupArray(), GetDefaultDecodingLookupArray(), false)(Name::AnyBase(), 34, true)));
}

const int *
Base34Decoder::GetDefaultDecodingLookupArray() {
    static bool s_initialized = false;
    static int s_array[256];

    if (!s_initialized) {
        InitializeDecodingLookupArray(s_array, s_vecUpper, (int)strlen((const char *)s_vecUpper), true);
        s_initialized = true;
    }
    return s_array;
}
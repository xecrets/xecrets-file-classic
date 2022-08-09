#ifndef AXSIGLIB_BASEM_H
#define AXSIGLIB_BASEM_H
/*! \file
	\brief AxSigLib - Short Elliptic Curve Digital Signature Algorithm et. al.

	@(#) $Id$

	Define some parameter values for BaseM encoding/decoding.

	AnyBase is the base of the representation
	BitPrecision is the total number of bits that the final representation is to have
		This is necessary to reserve the appropriate space etc. As a BaseM representation may
		not divide conveniently into a few bytes this gets a bit more complicated than for
		example base 8, base 16 or for that matter base 64.

	Copyright (C) 2005-2022 Svante Seleborg/Axon Data, All rights reserved.

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

#include "basecode.h"
#include "fltrimpl.h"

NAMESPACE_BEGIN(CryptoPP)
DOCUMENTED_NAMESPACE_BEGIN(Name)
CRYPTOPP_DEFINE_NAME_STRING(AnyBase)            //< int
CRYPTOPP_DEFINE_NAME_STRING(BitPrecision)       //< int
DOCUMENTED_NAMESPACE_END
NAMESPACE_END

USING_NAMESPACE(CryptoPP)

#endif
// This is always undefined here, so we always can #define it after inclusion of this header.
// You may, and should, include in every file where you use the assert macros.
#ifdef ASSERT_FILE
#undef ASSERT_FILE
#endif

#ifndef ASSERT_H
#define ASSERT_H
/*! \file
	\brief Assert.h - Convenience macros for assertions

	@(#) $Id$

	axcl - Xecrets File Classic support classes and types

	Copyright (C) 2008-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
#include <assert.h>

#ifndef ASSCHK
/// \brief Assert any custom condition
///
/// Do the if to ensure that the condition is evaluted before the call AssFunc, so that parameters
/// depending on that is properly passed to the function
/// \param fOk An expression that must validate to 'true'
/// \param sz A string with a message about the assertion.
#define ASSCHK(fOk, sz) { bool f = (fOk); assert((ASSERT_FILE, __LINE__, sz, f)); }
#endif

#ifndef ASSPTR
/// \brief Assert that a pointer is non-NULL
/// \param p A pointer expression that must not be NULL
#define ASSPTR(p) { bool f = (p) != NULL; assert((ASSERT_FILE, __LINE__, f)); }
#endif

#endif
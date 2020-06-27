/*! \file
	\brief XecretsFile2Go - Stand-Alone Install-free Ax Crypt for the road.

	This is the portable parts of the main program. OS-dependent parts, including the actual
	entry-point, must be compiled and linked separately.

	The Windows entrypoint is in XecretsFile2GoWin.cpp
	The *nix entry point might be in XecretsFile2GoUnix.cpp

	@(#) $Id$
*/
/*! \page License XecretsFile2Go - Stand-Alone Install-free Ax Crypt for the road

	Copyright (C) 2004 Svante Seleborg/Axon Data, All rights reserved.

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
//    version
//    htmlinclude Version.txt
/*! \mainpage XecretsFile2Go - Stand-Alone Install-free Ax Crypt for the road

	\author
	Svante Seleborg/Axantum Software AB

	\par License:
	\ref License "GNU General Public License"

	Internal Security design-goals: Uses a secure heap to attempt to keep passphrases out of
	memory, swap-files etc. Uses a subclassed passphrase entry dialog for the same reason. Wipes
	clear text after encryption.

	The design relies heavily on the <A HREF=http://axpipe.sourceforge.net>AxPipe</A> binary stream implementation.

	There is a GUI-aware part that presents the main window with an explorer like view. In that window
	right-click to encrypt and decrypt are supported, as are double-click to launch.

	You may also start the program with a file as a parameter.

	There is a non-GUI-aware part that does all the work, consisting of a number
	of AxPipe-style pipe sections doing things like skipping to the first
	file, parsing headers, check for cancel, decrypting, inflating, setting
	file times etc.

	Unicode is supported - and nothing else.

	The program starts as usual in ::WinMain().

	The decryption stream is passed through the following sections:

	CPipeAxCryptMeta    - Reads and buffers data, parsing headers into a CAxCryptMeta object. Sends the object
						  downstream, followed by the raw datastream with or without the headers.
	CPipeAxPromptKey    - Accepts an in-band CAxCryptMeta object, and prompts for a key. Sends it downstream
						  as CAxKeyMeta when ok, or aborts, followed by the raw unmodifed datastream. May
						  accept a parent window handle, or a pointer to a parent window handle.
	CPipeAxPromptFile   - Accepts an in-band CAxCryptMeta-object and a CAxKeyMeta, performs any GUI-related
						  prompting needed to determine location and file name, and sends a resulting CAxFileMeta-
						  object downstream.
	CPipeAxDecrypt      - Accepts an in-band key object, parses headers (again), uses the key to decrypt them.
						  Decrypts and decompresses and sends raw plain text down-stream. No GUI awareness.
	CSinkAxFile         - A CFileIO-derived sink that will accept a data-stream, and write it to
						  a specified file, using a CAxFileMeta-object to control the operation. No
						  GUI awareness.

	Objects used and passed thus include:

	CAxCryptMeta        - A collection of parsed headers, which may be encrypted or not. If a key
						  is present, they are decrypted and may be written and encrypted with this key.

	CAxFileMeta         - A set of file-related information necessary to re-create a file as it was,
						  including it's file-name, file-times and other meta-information that may
						  be relevant.

	CAxHMACMeta         - The calculated HMAC, ready for comparison with the one stored in the stream.

	CAxKeyMeta          - The master key encrypting key, derived from passphrase or whatever.

	CPipeAxDecrypt actually contains the following sections:

	CPipeAxCryptMeta    - Reads and buffers data, parsing headers into a CAxCryptMeta object. Sends the object
						  downstream, followed by the raw datastream with or without the headers.
	CPipeAxCalcHMAC     - Calculate HMAC. Receives CAxCryptMeta. Sends CAxHMACMeta. Also stores for later.
	CPipeAxDecryptData  - Actually decrypts the data stream. Receives CAxCryptMeta.
	CPipeAxDecompress   - Decompress, if necessary. Recieves CAxCryptMeta.
	CPipeAxCheckHMAC    - Verify HMAC correctness. Receives CAxHMACMeta.

	Encryption:

	CPipeAxPromptKey    - Accepts an in-band CAxCryptMeta object, and prompts for a key. Sends it downstream
						  as CAxKeyMeta when ok, or aborts, followed by the raw unmodifed datastream.
	CPipeAxPromptFile   - Accepts an in-band CAxFileMeta-object and performs any GUI-related prompting needed,
						  possibly modifying the object and sending it onwards.
	CPipeAxEncrypt      - Receives CAxCryptMeta (decrypted) w/key through Init()-call or in-band signalling.
						  Sends a complete file-stream (except HMAC which must be fixed up).
	CSinkAxFile         - A CFileIO-derived sink that will accept a data-stream, and write it to
						  a specified file, using a CAxFileMeta-object to control the operation. No
						  GUI awareness.

	CPipeAxEncrypt actually contains the following sections:

	CPipeAxWriteHeaders - Write the info in the headers, encrypted.
	CPipeAxCompress     - Compress if determined useful. Compression ratio needed set through Init()-call.
	CPipeAxEncryptData  - Actually encrypt the data datastream. Receives AxCryptMeta.
	CPipeAxCalcHMAC     - Calculate HMAC. Receives CAxCryptMeta. Sends CAxHMACMeta. Also stores for later.

*/
#include "stdafx.h"

#include "../AxPipe/AxPipe.h"

#include "../AxWinLib/AxAssert.h"
#define AXLIB_ASSERT_FILE "Crypt2Go.cpp"

// This just has to exist
AxPipe::CGlobalInit AxPipeGlobalInit;
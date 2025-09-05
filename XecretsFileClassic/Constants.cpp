/*
	@(#) $Id$

	Xecrets File Classic - Compressing and Encrypting Wrapper and Application Launcher for Secure Local,
	Server or Web Storage of Document Files.

	Copyright (C) 2001-2025 Svante Seleborg/Axantum Software AB. All rights reserved.

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
	Constants.cpp

	E-mail							YYYY-MM-DD				Reason
	support@axantum.com 			2001					Initial

*/
//
//	Define string constants etc here
//
#include	"StdAfx.h"
//
//
// From http://www.hclrss.demon.co.uk/demos/ansi.html
//
//	Define the allowed characters in a passphrase.
//
//	This is somewhat ad-hoc, but the idea is to allow as many as possible, without
//	encouraging things which really may be hard for the user to reproduce, especially
//	on a keyboard of another nationality than the native one. Also some which can cause
//	confusion depending on typed sequence are removed, such as all stand-alone umlauts
//	and such.
//
//	To allow people to use their native language in passphrases as easily as possible, most
//	variants of Latin characters are retained as valid.
//
const unsigned char szPassphraseChars[] = {
	0x20, // 0x0020, ' '			space Basic Latin
	0x21, // 0x0021, !				exclamation mark Basic Latin
	0x22, // 0x0022, "   &quot;		quotation mark Basic Latin
	0x23, // 0x0023, #				number sign Basic Latin
	0x24, // 0x0024, $				dollar sign Basic Latin
	0x25, // 0x0025, %				percent sign Basic Latin
	0x26, // 0x0026, &   &amp;		ampersand Basic Latin
	0x27, // 0x0027, '				apostrophe Basic Latin
	0x28, // 0x0028, (				left parenthesis Basic Latin
	0x29, // 0x0029, )				right parenthesis Basic Latin
	0x2A, // 0x002A, *				asterisk Basic Latin
	0x2B, // 0x002B, +				plus sign Basic Latin
	0x2C, // 0x002C, ,				comma Basic Latin
	0x2D, // 0x002D, -				hyphen-minus Basic Latin
	0x2E, // 0x002E, .				full stop Basic Latin
	0x2F, // 0x002F, /				solidus Basic Latin
	0x30, // 0x0030, 0				digit zero Basic Latin
	0x31, // 0x0031, 1				digit one Basic Latin
	0x32, // 0x0032, 2				digit two Basic Latin
	0x33, // 0x0033, 3				digit three Basic Latin
	0x34, // 0x0034, 4				digit four Basic Latin
	0x35, // 0x0035, 5				digit five Basic Latin
	0x36, // 0x0036, 6				digit six Basic Latin
	0x37, // 0x0037, 7				digit seven Basic Latin
	0x38, // 0x0038, 8				digit eight Basic Latin
	0x39, // 0x0039, 9				digit nine Basic Latin
	0x3A, // 0x003A, :				colon Basic Latin
	0x3B, // 0x003B, ;				semicolon Basic Latin
	0x3C, // 0x003C, <   &lt;		less-than sign Basic Latin
	0x3D, // 0x003D, =				equals sign Basic Latin
	0x3E, // 0x003E, >   &gt;		greater-than sign Basic Latin
	0x3F, // 0x003F, ?				question mark Basic Latin
	0x40, // 0x0040, @				commercial at Basic Latin
	0x41, // 0x0041, A				Latin capital letter A Basic Latin
	0x42, // 0x0042, B				Latin capital letter B Basic Latin
	0x43, // 0x0043, C				Latin capital letter C Basic Latin
	0x44, // 0x0044, D				Latin capital letter D Basic Latin
	0x45, // 0x0045, E				Latin capital letter E Basic Latin
	0x46, // 0x0046, F				Latin capital letter F Basic Latin
	0x47, // 0x0047, G				Latin capital letter G Basic Latin
	0x48, // 0x0048, H				Latin capital letter H Basic Latin
	0x49, // 0x0049, I				Latin capital letter I Basic Latin
	0x4A, // 0x004A, J				Latin capital letter J Basic Latin
	0x4B, // 0x004B, K				Latin capital letter K Basic Latin
	0x4C, // 0x004C, L				Latin capital letter L Basic Latin
	0x4D, // 0x004D, M				Latin capital letter M Basic Latin
	0x4E, // 0x004E, N				Latin capital letter N Basic Latin
	0x4F, // 0x004F, O				Latin capital letter O Basic Latin
	0x50, // 0x0050, P				Latin capital letter P Basic Latin
	0x51, // 0x0051, Q				Latin capital letter Q Basic Latin
	0x52, // 0x0052, R				Latin capital letter R Basic Latin
	0x53, // 0x0053, S				Latin capital letter S Basic Latin
	0x54, // 0x0054, T				Latin capital letter T Basic Latin
	0x55, // 0x0055, U				Latin capital letter U Basic Latin
	0x56, // 0x0056, V				Latin capital letter V Basic Latin
	0x57, // 0x0057, W				Latin capital letter W Basic Latin
	0x58, // 0x0058, X				Latin capital letter X Basic Latin
	0x59, // 0x0059, Y				Latin capital letter Y Basic Latin
	0x5A, // 0x005A, Z				Latin capital letter Z Basic Latin
	0x5B, // 0x005B, [				left square bracket Basic Latin
	0x5C, // 0x005C, \				reverse solidus Basic Latin
	0x5D, // 0x005D, ]				right square bracket Basic Latin
//	0x5E, // 0x005E, ^				circumflex accent Basic Latin
	0x5F, // 0x005F, _				low line Basic Latin
//	0x60, // 0x0060, `				grave accent Basic Latin
	0x61, // 0x0061, a				Latin small letter a Basic Latin
	0x62, // 0x0062, b				Latin small letter b Basic Latin
	0x63, // 0x0063, c				Latin small letter c Basic Latin
	0x64, // 0x0064, d				Latin small letter d Basic Latin
	0x65, // 0x0065, e				Latin small letter e Basic Latin
	0x66, // 0x0066, f				Latin small letter f Basic Latin
	0x67, // 0x0067, g				Latin small letter g Basic Latin
	0x68, // 0x0068, h				Latin small letter h Basic Latin
	0x69, // 0x0069, i				Latin small letter i Basic Latin
	0x6A, // 0x006A, j				Latin small letter j Basic Latin
	0x6B, // 0x006B, k				Latin small letter k Basic Latin
	0x6C, // 0x006C, l				Latin small letter l Basic Latin
	0x6D, // 0x006D, m				Latin small letter m Basic Latin
	0x6E, // 0x006E, n				Latin small letter n Basic Latin
	0x6F, // 0x006F, o				Latin small letter o Basic Latin
	0x70, // 0x0070, p				Latin small letter p Basic Latin
	0x71, // 0x0071, q				Latin small letter q Basic Latin
	0x72, // 0x0072, r				Latin small letter r Basic Latin
	0x73, // 0x0073, s				Latin small letter s Basic Latin
	0x74, // 0x0074, t				Latin small letter t Basic Latin
	0x75, // 0x0075, u				Latin small letter u Basic Latin
	0x76, // 0x0076, v				Latin small letter v Basic Latin
	0x77, // 0x0077, w				Latin small letter w Basic Latin
	0x78, // 0x0078, x				Latin small letter x Basic Latin
	0x79, // 0x0079, y				Latin small letter y Basic Latin
	0x7A, // 0x007A, z				Latin small letter z Basic Latin
	0x7B, // 0x007B, {				left curly bracket Basic Latin
	0x7C, // 0x007C, |				vertical line Basic Latin
	0x7D, // 0x007D, }				right curly bracket Basic Latin
//	0x7E, // 0x007E, ~				tilde Basic Latin
//	0x7F, // 0x007F, 				(not used) Basic Latin
	0x80, // 0x20AC, �   &euro;		euro sign Currency Symbols
//	0x81, // 0x0081, �				(not used)
//	0x82, // 0x201A, �   &sbquo;	single low-9 quotation mark General Punctuation
//	0x83, // 0x0192, �   &fnof;		Latin small letter f with hook Latin Extended-B
//	0x84, // 0x201E, �   &bdquo;	double low-9 quotation mark General Punctuation
//	0x85, // 0x2026, �   &hellip;	horizontal ellipsis General Punctuation
//	0x86, // 0x2020, �   &dagger;	dagger General Punctuation
//	0x87, // 0x2021, �   &Dagger;	double dagger General Punctuation
//	0x88, // 0x02C6, �   &circ;		modifier letter circumflex accent Spacing Modifier Letters
//	0x89, // 0x2030, �   &permil;	per mille sign General Punctuation
	0x8A, // 0x0160, �   &Scaron;	Latin capital letter S with caron Latin Extended-A
//	0x8B, // 0x2039, �   &lsaquo;	single left-pointing angle quotation mark General Punctuation
	0x8C, // 0x0152, �   &OElig;	Latin capital ligature OE Latin Extended-A
//	0x8D, // 0x008D, �				(not used)
	0x8E, // 0x017D, �				Latin capital letter Z with caron Latin Extended-A
//	0x8F, // 0x008F, �				(not used)
//	0x90, // 0x0090, �				(not used)
//	0x91, // 0x2018, �   &lsquo;	left single quotation mark General Punctuation
//	0x92, // 0x2019, �   &rsquo;	right single quotation mark General Punctuation
//	0x93, // 0x201C, �   &ldquo;	left double quotation mark General Punctuation
//	0x94, // 0x201D, �   &rdquo;	right double quotation mark General Punctuation
//	0x95, // 0x2022, �   &bull;		bullet General Punctuation
//	0x96, // 0x2013, �   &ndash;	en dash General Punctuation
//	0x97, // 0x2014, �   &mdash;	em dash General Punctuation
//	0x98, // 0x02DC, �   &tilde;	small tilde Spacing Modifier Letters
//	0x99, // 0x2122, �   &trade;	trade mark sign Letterlike Symbols
	0x9A, // 0x0161, �   &scaron;	Latin small letter s with caron Latin Extended-A
//	0x9B, // 0x203A, �   &rsaquo;	single right-pointing angle quotation mark General Punctuation
	0x9C, // 0x0153, �   &oelig;	Latin small ligature oe Latin Extended-A
//	0x9D, // 0x009D, �				(not used)
	0x9E, // 0x017E, �				Latin small letter z with caron Latin Extended-A
	0x9F, // 0x0178, �   &Yuml;		Latin capital letter Y with diaeresis Latin Extended-A
//	0xA0, // 0x00A0,	 &nbsp;		no-break space Latin-1 Supplement
	0xA1, // 0x00A1, �   &iexcl;	inverted exclamation mark Latin-1 Supplement
	0xA2, // 0x00A2, �   &cent;		cent sign Latin-1 Supplement
	0xA3, // 0x00A3, �   &pound;	pound sign Latin-1 Supplement
	0xA4, // 0x00A4, �   &curren;	currency sign Latin-1 Supplement
	0xA5, // 0x00A5, �   &yen;		yen sign Latin-1 Supplement
//	0xA6, // 0x00A6, �   &brvbar;	broken bar Latin-1 Supplement
	0xA7, // 0x00A7, �   &sect;		section sign Latin-1 Supplement
//	0xA8, // 0x00A8, �   &uml;		diaeresis Latin-1 Supplement
//	0xA9, // 0x00A9, �   &copy;		copyright sign Latin-1 Supplement
//	0xAA, // 0x00AA, �   &ordf;		feminine ordinal indicator Latin-1 Supplement
//	0xAB, // 0x00AB, �   &laquo;	left-pointing double angle quotation mark Latin-1 Supplement
//	0xAC, // 0x00AC, �   &not;		not sign Latin-1 Supplement
//	0xAD, // 0x00AD, �   &shy;		soft hyphen Latin-1 Supplement
//	0xAE, // 0x00AE, �   &reg;		registered sign Latin-1 Supplement
//	0xAF, // 0x00AF, �   &macr;		macron Latin-1 Supplement
//	0xB0, // 0x00B0, �   &deg;		degree sign Latin-1 Supplement
	0xB1, // 0x00B1, �   &plusmn;	plus-minus sign Latin-1 Supplement
//	0xB2, // 0x00B2, �   &sup2;		superscript two Latin-1 Supplement
//	0xB3, // 0x00B3, �   &sup3;		superscript three Latin-1 Supplement
//	0xB4, // 0x00B4, �   &acute;	acute accent Latin-1 Supplement
//	0xB5, // 0x00B5, �   &micro;	micro sign Latin-1 Supplement
//	0xB6, // 0x00B6, �   &para;		pilcrow sign Latin-1 Supplement
//	0xB7, // 0x00B7, �   &middot;	middle dot Latin-1 Supplement
//	0xB8, // 0x00B8, �   &cedil;	cedilla Latin-1 Supplement
//	0xB9, // 0x00B9, �   &sup1;		superscript one Latin-1 Supplement
//	0xBA, // 0x00BA, �   &ordm;		masculine ordinal indicator Latin-1 Supplement
//	0xBB, // 0x00BB, �   &raquo;	right-pointing double angle quotation mark Latin-1 Supplement
	0xBC, // 0x00BC, �   &frac14;	vulgar fraction one quarter Latin-1 Supplement
	0xBD, // 0x00BD, �   &frac12;	vulgar fraction one half Latin-1 Supplement
	0xBE, // 0x00BE, �   &frac34;	vulgar fraction three quarters Latin-1 Supplement
	0xBF, // 0x00BF, �   &iquest;	inverted question mark Latin-1 Supplement
	0xC0, // 0x00C0, �   &Agrave;	Latin capital letter A with grave Latin-1 Supplement
	0xC1, // 0x00C1, �   &Aacute;	Latin capital letter A with acute Latin-1 Supplement
	0xC2, // 0x00C2, �   &Acirc;	Latin capital letter A with circumflex Latin-1 Supplement
	0xC3, // 0x00C3, �   &Atilde;	Latin capital letter A with tilde Latin-1 Supplement
	0xC4, // 0x00C4, �   &Auml;		Latin capital letter A with diaeresis Latin-1 Supplement
	0xC5, // 0x00C5, �   &Aring;	Latin capital letter A with ring above Latin-1 Supplement
	0xC6, // 0x00C6, �   &AElig;	Latin capital letter AE Latin-1 Supplement
	0xC7, // 0x00C7, �   &Ccedil;	Latin capital letter C with cedilla Latin-1 Supplement
	0xC8, // 0x00C8, �   &Egrave;	Latin capital letter E with grave Latin-1 Supplement
	0xC9, // 0x00C9, �   &Eacute;	Latin capital letter E with acute Latin-1 Supplement
	0xCA, // 0x00CA, �   &Ecirc;	Latin capital letter E with circumflex Latin-1 Supplement
	0xCB, // 0x00CB, �   &Euml;		Latin capital letter E with diaeresis Latin-1 Supplement
	0xCC, // 0x00CC, �   &Igrave;	Latin capital letter I with grave Latin-1 Supplement
	0xCD, // 0x00CD, �   &Iacute;	Latin capital letter I with acute Latin-1 Supplement
	0xCE, // 0x00CE, �   &Icirc;	Latin capital letter I with circumflex Latin-1 Supplement
	0xCF, // 0x00CF, �   &Iuml;		Latin capital letter I with diaeresis Latin-1 Supplement
	0xD0, // 0x00D0, �   &ETH;		Latin capital letter Eth Latin-1 Supplement
	0xD1, // 0x00D1, �   &Ntilde;	Latin capital letter N with tilde Latin-1 Supplement
	0xD2, // 0x00D2, �   &Ograve;	Latin capital letter O with grave Latin-1 Supplement
	0xD3, // 0x00D3, �   &Oacute;	Latin capital letter O with acute Latin-1 Supplement
	0xD4, // 0x00D4, �   &Ocirc;	Latin capital letter O with circumflex Latin-1 Supplement
	0xD5, // 0x00D5, �   &Otilde;	Latin capital letter O with tilde Latin-1 Supplement
	0xD6, // 0x00D6, �   &Ouml;		Latin capital letter O with diaeresis Latin-1 Supplement
//	0xD7, // 0x00D7, �   &times;	multiplication sign Latin-1 Supplement
	0xD8, // 0x00D8, �   &Oslash;	Latin capital letter O with stroke Latin-1 Supplement
	0xD9, // 0x00D9, �   &Ugrave;	Latin capital letter U with grave Latin-1 Supplement
	0xDA, // 0x00DA, �   &Uacute;	Latin capital letter U with acute Latin-1 Supplement
	0xDB, // 0x00DB, �   &Ucirc;	Latin capital letter U with circumflex Latin-1 Supplement
	0xDC, // 0x00DC, �   &Uuml;		Latin capital letter U with diaeresis Latin-1 Supplement
	0xDD, // 0x00DD, �   &Yacute;	Latin capital letter Y with acute Latin-1 Supplement
	0xDE, // 0x00DE, �   &THORN;	Latin capital letter Thorn Latin-1 Supplement
	0xDF, // 0x00DF, �   &szlig;	Latin small letter sharp s Latin-1 Supplement
	0xE0, // 0x00E0, �   &agrave;	Latin small letter a with grave Latin-1 Supplement
	0xE1, // 0x00E1, �   &aacute;	Latin small letter a with acute Latin-1 Supplement
	0xE2, // 0x00E2, �   &acirc;	Latin small letter a with circumflex Latin-1 Supplement
	0xE3, // 0x00E3, �   &atilde;	Latin small letter a with tilde Latin-1 Supplement
	0xE4, // 0x00E4, �   &auml;		Latin small letter a with diaeresis Latin-1 Supplement
	0xE5, // 0x00E5, �   &aring;	Latin small letter a with ring above Latin-1 Supplement
	0xE6, // 0x00E6, �   &aelig;	Latin small letter ae Latin-1 Supplement
	0xE7, // 0x00E7, �   &ccedil;	Latin small letter c with cedilla Latin-1 Supplement
	0xE8, // 0x00E8, �   &egrave;	Latin small letter e with grave Latin-1 Supplement
	0xE9, // 0x00E9, �   &eacute;	Latin small letter e with acute Latin-1 Supplement
	0xEA, // 0x00EA, �   &ecirc;	Latin small letter e with circumflex Latin-1 Supplement
	0xEB, // 0x00EB, �   &euml;		Latin small letter e with diaeresis Latin-1 Supplement
	0xEC, // 0x00EC, �   &igrave;	Latin small letter i with grave Latin-1 Supplement
	0xED, // 0x00ED, �   &iacute;	Latin small letter i with acute Latin-1 Supplement
	0xEE, // 0x00EE, �   &icirc;	Latin small letter i with circumflex Latin-1 Supplement
	0xEF, // 0x00EF, �   &iuml;		Latin small letter i with diaeresis Latin-1 Supplement
	0xF0, // 0x00F0, �   &eth;		Latin small letter eth Latin-1 Supplement
	0xF1, // 0x00F1, �   &ntilde;	Latin small letter n with tilde Latin-1 Supplement
	0xF2, // 0x00F2, �   &ograve;	Latin small letter o with grave Latin-1 Supplement
	0xF3, // 0x00F3, �   &oacute;	Latin small letter o with acute Latin-1 Supplement
	0xF4, // 0x00F4, �   &ocirc;	Latin small letter o with circumflex Latin-1 Supplement
	0xF5, // 0x00F5, �   &otilde;	Latin small letter o with tilde Latin-1 Supplement
	0xF6, // 0x00F6, �   &ouml;		Latin small letter o with diaeresis Latin-1 Supplement
//	0xF7, // 0x00F7, �   &divide;	division sign Latin-1 Supplement
	0xF8, // 0x00F8, �   &oslash;	Latin small letter o with stroke Latin-1 Supplement
	0xF9, // 0x00F9, �   &ugrave;	Latin small letter u with grave Latin-1 Supplement
	0xFA, // 0x00FA, �   &uacute;	Latin small letter u with acute Latin-1 Supplement
	0xFB, // 0x00FB, �   &ucirc;	Latin small letter with circumflex Latin-1 Supplement
	0xFC, // 0x00FC, �   &uuml;		Latin small letter u with diaeresis Latin-1 Supplement
	0xFD, // 0x00FD, �   &yacute;	Latin small letter y with acute Latin-1 Supplement
	0xFE, // 0x00FE, �   &thorn;	Latin small letter thorn Latin-1 Supplement
	0xFF, // 0x00FF, �   &yuml;		Latin small letter y with diaeresis Latin-1 Supplement
	0
};
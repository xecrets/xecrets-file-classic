// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//
#pragma once

// XecretsFileLib is operating system independent, and Visual Studio 2005 and later have special
// 'secure' replacements for strcpy et. al. - but we want to be independent of such vendor
// specific extensions in this library, so we disable the Visual Studio warnings.
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_RAND_S

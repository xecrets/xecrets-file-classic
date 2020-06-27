This project is only here to fix an issue with MSBUild / Visual Studio dependency ordering
of projects.

We have AxDecrypt which references XecretsFileCommon which references XecretsFileMessages.

XecretsFileMessages must be built before XecretsFileCommon, becuase it produces the AxCryptTexts.h
header file, needed by XecretsFileCommon.

The problem is that if we reference XecretsFileMessages from XecretsFileCommon, then Visual Studio or MSBuild
get's the brilliant idea that it must add 'XecretsFileMessages.lib' to the linkage of AxDecrypt. There is
no XecretsFileMessages.lib since it's a dll. I could not find a way to get it to do this right.

The solution was to have XecretsFileCommon reference this dummy project (which is an .exe, not a .lib) and
then have this project reference XecretsFileMessages.

This appears to work from Visual Studio and MSBuild command line.

Just ignore the executable output.

(TODO - Remove the dependency on XecretsFileMessages from XecretsFileCommon - it won't work anyway since we
don't distribute XecretsFileMessages with AxDecrypt....)

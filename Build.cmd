call "%VSINSTALLDIR%vc\Auxiliary\Build\vcvarsall" x86
MSBuild XecretsFile.sln /p:Configuration=Debug;Platform=Win32
MSBuild XecretsFile.sln /p:Configuration=Release;Platform=Win32
call "%VSINSTALLDIR%vc\Auxiliary\Build\vcvarsall" amd64
MSBuild XecretsFile.sln /p:Configuration=Debug;Platform=x64
MSBuild XecretsFile.sln /p:Configuration=Release;Platform=x64
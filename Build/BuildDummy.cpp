// It turns out to be easiest to simply build a dummy static library in order to get Visual Studio to
// do the right thing vis-a-vis dependency analysis. Tried with 'Utility', but it was hard to get it
// to pick up the dependencies, i.e. I failed and this seemed easier.
namespace XecretsFileClassic {
	extern int BuildDummy =
#include "Version.txt"
		;
};
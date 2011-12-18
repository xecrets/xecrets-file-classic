#ifndef _SHA1
#define _SHA1

#define SHA1HANDSOFF				// Svante Seleborg

typedef struct {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
#ifdef	SHA1HANDSOFF				// Svante Seleborg
	unsigned char workspace[64];	// Svante Seleborg
#endif								// Svante Seleborg
} SHA1_CTX;

void SHA1Transform(SHA1_CTX* context, unsigned char buffer[64]);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, unsigned char* data, unsigned int len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);
#endif _SHA1

#ifndef HASH3_H
#define HASH3_H

#include <stdint.h>
#include <assert.h>
#include "uint256.h"

using namespace std;

void crypto_hash(uint256 *out, const uint8_t *in, uint64_t inlen);

inline uint256 Hash3(const char *pbegin, const char *pend)
{
	assert(pbegin != pend);
	assert((pend - pbegin) * sizeof(pbegin[0]) == 80);

    uint256 hash1;
    uint256 hash2;
    crypto_hash(&hash1, (const uint8_t*)pbegin, (pend - pbegin) * sizeof(pbegin[0]));
    crypto_hash(&hash2, (uint8_t*)&hash1, sizeof(hash1));
    return hash2;
}

#endif // HASH3_H

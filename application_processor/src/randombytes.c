#include "trng.h"

void randombytes(uint8_t *buf, int num_bytes)
{
    memset(buf, 0, sizeof(buf));

    MXC_TRNG_Init();

    MXC_TRNG_Random(buf, num_bytes);

    MXC_TRNG_Shutdown();
}
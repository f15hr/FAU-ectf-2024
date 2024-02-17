#include "trng.h"

unsigned int get_random_trng(void) {
    uint8_t var_rnd_no[4] = {0};
    MXC_TRNG_Random(var_rnd_no, 4);
    return *((unsigned int *)var_rnd_no);
}
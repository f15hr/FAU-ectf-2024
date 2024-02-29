#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "nvic_table.h"
#include "trng.h"

// void print(char *stuff)
// {
//     int i, j, size = 4;

//     for (i = 0; i < 4; ++i) {
//         for (j = 0; j < 4; ++j) {
//             printf("0x%02x ", stuff[i * size + j]);
//         }

//         printf("\n");
//     }

//     return;
// }

void randombytes(uint8_t *var_rnd_no, int num_bytes)
{

    memset(var_rnd_no, 0, sizeof(var_rnd_no));

    MXC_TRNG_Init();

    MXC_TRNG_Random(var_rnd_no, num_bytes);

    print((char *)var_rnd_no);

    MXC_TRNG_Shutdown();
}
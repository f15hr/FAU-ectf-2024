#ifndef __RANDOMBYTES__
#define __HRANDOMBYTES__

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "nvic_table.h"

// Generate Random bytes
void randombytes(uint8_t *buf, int num_bytes);


#endif

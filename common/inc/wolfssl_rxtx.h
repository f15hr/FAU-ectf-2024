#include "wolfssl/wolfssl/ssl.h"\

extern i2c_addr_t;

#ifndef MAX_RECORD_SIZE
#define MAX_RECORD_SIZE (8 * 1024)
#endif

typedef struct {
    int curr_index;
    int data_len;
    char buf[MAX_RECORD_SIZE];
    i2c_addr_t addr;
} tls13_buf;

int i2cwolf_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int i2cwolf_send(WOLFSSL* ssl, char* buf, int sz, void* ctx);
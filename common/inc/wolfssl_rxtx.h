#include "wolfssl/wolfssl/ssl.h"

int i2cwolf_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int i2cwolf_send(WOLFSSL* ssl, char* buf, int sz, void* ctx);
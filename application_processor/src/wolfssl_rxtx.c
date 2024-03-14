#include "board_link.h"
#include "wolfssl_rxtx.h"
#include "secrets_ap.h"
#include "wolfssl/wolfssl/ssl.h"
#include "host_messaging.h"
#include <stdio.h>


int i2cwolf_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx) {

    tls13_buf *tb = ctx;

    if (tb->curr_index == 0) {
        XMEMSET(tb->buf, 0, MAX_RECORD_SIZE);
        int len = poll_and_receive_packet(tb->addr, tb->buf);
        if (len == ERROR_RETURN) {
            return -1;
        }
        tb->data_len = len;
    }

    // Handle the case where sz > MAX_I2C_MESSAGE_LEN
    while (tb->data_len < (sz + tb->curr_index)) {
        int len = poll_and_receive_packet(tb->addr, tb->buf + tb->data_len);
        if (len == ERROR_RETURN) {
            return -1;
        }
        tb->data_len += len;
    }

    XMEMCPY(buf, tb->buf + tb->curr_index, sz);
    tb->curr_index += sz;

    // If the last portion of the buffer was just read,
    // set the curr_index to 0 to reset the state.
    if (tb->curr_index == tb->data_len) {
        tb->curr_index = 0;
    } 

    return sz;
}

int i2cwolf_send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {

    tls13_buf *tb = ctx;
    int ret = sz;
    (void)ctx;

    int i = 0;
    uint16_t len = (uint16_t)sz;
    
    // Handle the case where sz > MAX_I2C_MESSAGE_LEN
    while (len > MAX_I2C_MESSAGE_LEN-1) {
        int result = send_packet(tb->addr, MAX_I2C_MESSAGE_LEN-1, buf + i);
        if (result == ERROR_RETURN) {
            ret = -1;
        }
        len -= MAX_I2C_MESSAGE_LEN-1;
        i += MAX_I2C_MESSAGE_LEN-1;
    }

    if (len == 0)
        return ret;
        
    int result = send_packet(tb->addr, len, buf + i);
    if (result == ERROR_RETURN) {
        ret = -1;
    }

    return ret;
}


tls13_buf* ssl_new_buf(uint32_t component_id) {
    tls13_buf *tbuf = (tls13_buf *)malloc(sizeof(tls13_buf));
    XMEMSET(tbuf, 0, sizeof(tls13_buf));
    tbuf->addr = component_id_to_i2c_addr(component_id);

    return tbuf;
}

WOLFSSL_CTX* ssl_new_context_client() {
    WOLFSSL_CTX* ctx;
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if(ctx == 0) {
        #ifdef DEBUG
        printf("Failed to create WolfSSL CTX");
        #endif
        return -1;
    }

    wolfSSL_CTX_SetIOSend(ctx, i2cwolf_send);
    wolfSSL_CTX_SetIORecv(ctx, i2cwolf_receive); 

    wolfSSL_CTX_use_PrivateKey_buffer(ctx, KEY_DEVICE, sizeof(KEY_DEVICE), SSL_FILETYPE_PEM);

    int verify_buffer = wolfSSL_CTX_load_verify_buffer_ex(ctx, PEM_CA, sizeof(PEM_CA), SSL_FILETYPE_PEM, 0, 1);
    if(verify_buffer != WOLFSSL_SUCCESS) {
        #ifdef DEBUG
        printf("Failed to create verufy buffer");
        #endif
        return NULL;
    }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    return ctx;
}

WOLFSSL* ssl_new_session(WOLFSSL_CTX *ctx, tls13_buf *tbuf) {
    WOLFSSL *ssl;
    ssl = wolfSSL_new(ctx);
    if(ssl == 0) {
        #ifdef DEBUG
        printf("Failed to create WolfSSL object");
        #endif
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    wolfSSL_SetIOReadCtx(ssl, tbuf);
    wolfSSL_SetIOWriteCtx(ssl, tbuf);

    return ssl;
}

int ssl_connect(WOLFSSL *ssl, tls13_buf *tbuf) {
    int ret = 0;
    int err = 0;
    do {
        ret = wolfSSL_connect(ssl);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);
    if (ret != WOLFSSL_SUCCESS) {
        #ifdef DEBUG
        printf("TLS connect error %d\n", err);
        #endif
        return -1;
    }

    // Reset communication state
    tbuf->curr_index = 0;
    tbuf->data_len = 0;

    return 0;
}

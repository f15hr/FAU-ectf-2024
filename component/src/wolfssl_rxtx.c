#include <icc.h>
#include <stdio.h>

#include "board_link.h"
#include "wolfssl_rxtx.h"
#include "wolfssl/wolfssl/ssl.h"
#include "secrets_component.h"



int __attribute__((noinline, optimize(0))) i2cwolf_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx) {

    tls13_buf *tb = ctx;

    if (tb->curr_index == 0) {
        XMEMSET(tb->buf, 0, MAX_RECORD_SIZE);
        I2C_REGS[RECEIVE_DONE][0] = false;
        I2C_REGS[TRANSMIT_DONE][0] = false;
        int len = wait_and_receive_packet(tb->buf);
        if (len == ERROR_RETURN) {
            return -1;
        }
        tb->data_len = len;
    }

    // Handle the case where sz > MAX_I2C_MESSAGE_LEN
    while (tb->data_len < (sz + tb->curr_index)) {
        I2C_REGS[RECEIVE_DONE][0] = false;
        I2C_REGS[TRANSMIT_DONE][0] = false;
        int len = wait_and_receive_packet(tb->buf + tb->data_len);
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

int __attribute__((noinline, optimize(0))) i2cwolf_send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {

    int ret = sz;
    (void)ctx;

    int i = 0;
    uint16_t len = (uint16_t)sz;
    
    // Handle the case where sz > MAX_I2C_MESSAGE_LEN
    while (len > MAX_I2C_MESSAGE_LEN-1) {
        I2C_REGS[RECEIVE_DONE][0] = true;
        I2C_REGS[TRANSMIT_DONE][0] = false;
        send_packet_and_ack(MAX_I2C_MESSAGE_LEN-1, buf + i);
        len -= MAX_I2C_MESSAGE_LEN-1;
        i += MAX_I2C_MESSAGE_LEN-1;
    }

    if (len == 0)
        return ret;
        
    I2C_REGS[RECEIVE_DONE][0] = true;
    I2C_REGS[TRANSMIT_DONE][0] = false;
    send_packet_and_ack(len, buf + i);
    
    return ret;
}

tls13_buf* ssl_new_buf(i2c_addr_t addr) {
    tls13_buf *tbuf = (tls13_buf *)malloc(sizeof(tls13_buf));
    XMEMSET(tbuf, 0, sizeof(tls13_buf));
    tbuf->addr = addr;

    return tbuf;
}


WOLFSSL_CTX* __attribute__((noinline, optimize(0))) ssl_new_context_server() {
    WOLFSSL_CTX* ctx;
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if(ctx == NULL) {
        #ifdef DEBUG
        printf("Failed to create WolfSSL CTX");
        #endif
        return -1;
    }

    wolfSSL_CTX_SetIOSend(ctx, i2cwolf_send);
    wolfSSL_CTX_SetIORecv(ctx, i2cwolf_receive); 

    wolfSSL_CTX_use_PrivateKey_buffer(ctx, KEY_DEVICE, sizeof(KEY_DEVICE), SSL_FILETYPE_PEM);
    wolfSSL_CTX_use_certificate_buffer(ctx, PEM_DEVICE, sizeof(PEM_DEVICE), SSL_FILETYPE_PEM);

    int cipherlist = wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES128-GCM-SHA256");
    if(cipherlist != WOLFSSL_SUCCESS) {
        #ifdef DEBUG
        printf("Failed to set cipher list");
        #endif
        return NULL;
    }

    // int verify_buffer = wolfSSL_CTX_load_verify_buffer_ex(ctx, PEM_CA, sizeof(PEM_CA), SSL_FILETYPE_PEM, 0, 1);
    int verify_buffer = wolfSSL_CTX_load_verify_buffer(ctx, PEM_CA, sizeof(PEM_CA), SSL_FILETYPE_PEM);
    
    if(verify_buffer != WOLFSSL_SUCCESS) {
        #ifdef DEBUG
        printf("Failed to create verufy buffer");
        #endif
        return NULL;
    }

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_CLIENT_ONCE, NULL);

    return ctx;
}


WOLFSSL* __attribute__((noinline, optimize(0))) ssl_new_session(WOLFSSL_CTX *ctx, tls13_buf *tbuf) {
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

int __attribute__((noinline, optimize(0))) ssl_handshake_server(WOLFSSL *ssl, tls13_buf *tbuf) {
    int ret = 0;
    int err = 0;

    MXC_ICC_Enable(MXC_ICC0);

    // I2C_REGS[RECEIVE_DONE][0] = false;
    // I2C_REGS[TRANSMIT_DONE][0] = false;

    do {
        ret = wolfSSL_accept(ssl);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);
    if (ret != WOLFSSL_SUCCESS) {
        #ifdef DEBUG
        printf("TLS accept error %d\n", err);
        #endif
        return -1;
    }

    MXC_ICC_Disable(MXC_ICC0);

    // Reset communication state
    tbuf->curr_index = 0;
    tbuf->data_len = 0;
    I2C_REGS[RECEIVE_DONE][0] = false;
    I2C_REGS[TRANSMIT_DONE][0] = true;

    return WOLFSSL_SUCCESS;
}


int ssl_free_all(WOLFSSL_CTX *ctx, WOLFSSL *ssl, tls13_buf *tbuf) {
    wolfSSL_CTX_free(ctx);
    wolfSSL_free(ssl);
    free(tbuf);
}

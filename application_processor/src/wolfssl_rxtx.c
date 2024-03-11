#include "board_link.h"
#include "wolfssl_rxtx.h"

#include "wolfssl/wolfssl/ssl.h"


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

    int result = send_packet(tb->addr, len, buf + i);
    if (result == ERROR_RETURN) {
        ret = -1;
    }

    return ret;
}

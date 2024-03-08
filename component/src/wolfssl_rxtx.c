#include "board_link.h"
#include "wolfssl_rxtx.h"
#include "wolfssl/wolfssl/ssl.h"



int i2cwolf_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx) {

    tls13_buf *tb = ctx;

    if (tb->curr_index == 0) {
        XMEMSET(tb->buf, 0, MAX_RECORD_SIZE);
        int len = wait_and_receive_packet(tb->buf);
        if (len == ERROR_RETURN) {
            return -1;
        }
        tb->data_len = len;
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

    int ret = sz;
    (void)ctx;

    send_packet_and_ack(sz, buf);

    // XMEMCPY(buf, tb->buf, sz);
    // tb->data_len = msg_length;
    // tb->curr_index = sz;
    
    return ret;
}

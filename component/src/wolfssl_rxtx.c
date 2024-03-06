#include "board_link.h"
#include "wolfssl_rxtx.h"
#include "wolfssl/wolfssl/ssl.h"



int i2cwolf_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx) {

    tls13_buf *tb = ctx;
    int msg_length = 0;

    // i2c_addr_t addr = component_id_to_i2c_addr(0x11111124);

    if (tb->curr_index + sz <= tb->data_len) {
        XMEMCPY(buf, tb->buf + tb->curr_index, sz);
        tb->curr_index += sz;
        return sz;
    }

    msg_length = 0;
    XMEMSET(tb, 0, sizeof(*tb));

    int len = wait_and_receive_packet(tb->buf);
    if (len == ERROR_RETURN) {
        return -1;
    }

    XMEMCPY(buf, tb->buf, sz);
    tb->data_len = msg_length;
    tb->curr_index = sz;

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

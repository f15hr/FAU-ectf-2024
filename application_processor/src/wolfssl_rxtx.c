#include "board_link.h"

#include "wolfssl/wolfssl/ssl.h"


int i2cwolf_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx) {

    i2c_addr_t addr = component_id_to_i2c_addr(0x11111124);

    int len = poll_and_receive_packet(addr, buf);

    return sz;
}

int i2cwolf_send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    i2c_addr_t addr = component_id_to_i2c_addr(0x11111124);

    int result = send_packet(addr, sz, buf);

    if (result == ERROR_RETURN) {
        return -1;
    }
    
    return sz;
}
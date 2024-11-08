/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "i2s.h"
#include "cameraif.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include "trng.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"

#include "wolfssl/wolfssl/ssl.h"
#include "wolfssl_rxtx.h"
#include "rng.h"

// Includes from containerized build
#include "ectf_params.h"

#include "secrets_component.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

#define print_info(...) printf("%%info: "); printf(__VA_ARGS__); printf("%%"); fflush(stdout)
#define print_hex_info(...) printf("%%info: "); print_hex(__VA_ARGS__); printf("%%"); fflush(stdout)

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int __attribute__((noinline, optimize(0))) secure_send(uint8_t* buffer, uint8_t len) {
    if (get_random_trng() == ERROR_RETURN){
        return ERROR_RETURN;
    }
    int ret = 0;
    int err = 0;
    uint8_t snd_len[1] = {len};

    // Ensure I2C register flags have expected value.
    // Sometimes these are not set properly
    I2C_REGS[TRANSMIT_LEN][0] = 0;
    I2C_REGS[RECEIVE_LEN][0] = 0;

    // Init wolfSSL library
    // Technically we should do this once, but
    // we want to ensure every invocation of wolfSSL
    // is a fresh state
    wolfSSL_Init();

    tls13_buf *tbuf; 
    WOLFSSL_CTX *ctx; 
    WOLFSSL *ssl; 
    do {
        tbuf = ssl_new_buf(0);
        ctx = ssl_new_context_server();
        ssl = ssl_new_session(ctx, tbuf);
        ret = ssl_handshake_server(ssl, tbuf);
    } while (ret == -1);

    // Send length of data to transmit via wolfSSL
    do {
        ret = wolfSSL_write(ssl, snd_len, 1);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    // Error, free all memory
    if (ret <= 0) {
        ssl_free_all(ctx, ssl, tbuf);
        
        return ERROR_RETURN;
    }

    // Send data via wolfSSL
    do {
        ret = wolfSSL_write(ssl, buffer, len);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    // Error, free all memory
    if (ret <= 0) {
        ssl_free_all(ctx, ssl, tbuf);
        
        return ERROR_RETURN;
    }

    // Free all memory
    ssl_free_all(ctx, ssl, tbuf);
    wolfSSL_Cleanup();
    
    return ret;
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int __attribute__((noinline, optimize(0))) secure_receive(uint8_t* buffer) {
    if (get_random_trng() == ERROR_RETURN){
        return ERROR_RETURN;
    }
    int ret = 0;
    int err = 0;
    uint8_t rcv_len[1] = {0};

    // Ensure I2C register flags have expected value.
    // Sometimes these are not set properly
    I2C_REGS[TRANSMIT_LEN][0] = 0;
    I2C_REGS[RECEIVE_LEN][0] = 0;

    wolfSSL_Init();

    tls13_buf *tbuf; 
    WOLFSSL_CTX *ctx; 
    WOLFSSL *ssl; 
    do {
        tbuf = ssl_new_buf(0);
        ctx = ssl_new_context_server();
        ssl = ssl_new_session(ctx, tbuf);
        ret = ssl_handshake_server(ssl, tbuf);
    } while (ret == -1);

    // Get length of data being transmitted via wolfSSL
    do {
        ret = wolfSSL_read(ssl, rcv_len, 1);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    // Error, free all memory
    if (ret <= 0) {
        ssl_free_all(ctx, ssl, tbuf);
        return ERROR_RETURN;
    }

    uint8_t t_len = rcv_len[0];

    // Receive data via wolfSSL
    do {
        ret = wolfSSL_read(ssl, buffer, t_len);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    // Error, free all memory
    if (ret <= 0) {
        ssl_free_all(ctx, ssl, tbuf);
        
        return ERROR_RETURN;
    }

    // Free all memory
    ssl_free_all(ctx, ssl, tbuf);
    wolfSSL_Cleanup();
    
    return ret;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {
    

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
    
}

// Handle a transaction from the AP
void component_process_cmd() {
    
    command_message* command = (command_message*) receive_buffer;

    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_VALIDATE:
        process_validate();
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
    
}

void process_boot() {
    
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    process_validate();
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    secure_send(transmit_buffer, len);
    // Call the boot function
    boot();
    
}

void process_scan() {
    
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    secure_send(transmit_buffer, sizeof(scan_message));
    
}

void process_validate() {
    
    // The AP requested a validation. Respond with the Component ID
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    secure_send(transmit_buffer, sizeof(validate_message));
    
}

void process_attest() {
    
    // The AP requested attestation. Respond with the attestation data

    /****************************************************************************
     * TODO: CHECK SPRINTF MIGHT BE SUS.
    ****************************************************************************/
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    secure_send(transmit_buffer, len);
    
}

/**
 * @brief Receives a wake command from the AP
 * 
 * @return int: Number of bytes received from the AP
*/
int wake_comp() {
    
    uint8_t data[1] = {0};
    
    int len = wait_and_receive_packet(data);
    if (len == ERROR_RETURN) {
        
        return ERROR_RETURN;
    }

    send_packet_and_ack(len, data);
    
    return len;
}

/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();

    // Increase clock speed to 100 MHz (Hopefully :))
    MXC_SYS_Clock_Select(MXC_SYS_CLOCK_IPO);
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);

    // Initialize the TRNG hardware
    MXC_TRNG_Init();

    // Disable the audio jacks
    MXC_I2S_TXDisable();
    MXC_I2S_RXDisable();

    // Disable camera
    MXC_PCIF_Stop();

    LED_On(LED2); 

    while (1) {

        I2C_REGS[TRANSMIT_DONE][0] = false;

        wake_comp();
        secure_receive(receive_buffer);
        component_process_cmd();
    }
}

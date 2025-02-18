/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pin_mux.h"
#include "board.h"
#include "fsl_debug_console.h"
#include "fsl_gpio.h"

#include "fsl_clock.h"
#include "fsl_reset.h"
#include <stdbool.h>
#include <string.h>
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define BOARD_LED_GPIO     BOARD_LED_RED_GPIO
#define BOARD_LED_GPIO_PIN BOARD_LED_RED_GPIO_PIN

/* Definition of function to rotation bits */
#define RL32(value, quantity) ((value << quantity) | (value >> (32 - quantity)))

/* Definition of quantity iterations */
#define iterations 10

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/* Function to calculate rotation left */
static void CHACHA20_QR(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);

/* Function to iteration of Chacha20. 20 rounds to generate a block of 64 bytes */
static void CHACHA20_Block(uint32_t state[16], uint8_t output[64]);

/* Function to encrypt using Chacha20 */
static void CHACHA20_Encrypt(uint8_t *plaintext, uint8_t *ciphertext, uint32_t length, uint32_t key[8], uint32_t nonce[3], uint32_t counter);

/*!
 * @brief delay a while.
 */
void delay(void);

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/* Implementation of the function to rotation left */
static void CHACHA20_QR(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
	*a += *b; *d ^= *a; *d = RL32(*d, 16);
	*c += *d; *b ^= *c; *b = RL32(*b, 12);
	*a += *b; *d ^= *a; *d = RL32(*d, 8);
	*c += *d; *b ^= *c; *b = RL32(*b, 7);
}

/* Implementation of the function to generate block */
static void CHACHA20_Block(uint32_t state[16], uint8_t output[64]) {
	uint32_t ws[16] = {0};
	memcpy(&ws[0], &state[0], sizeof(ws));

	for (int i = 0; i < iterations; i++) {
		//Columns
		CHACHA20_QR(&ws[0], &ws[4], &ws[8],  &ws[12]);
		CHACHA20_QR(&ws[1], &ws[5], &ws[9],  &ws[13]);
		CHACHA20_QR(&ws[2], &ws[6], &ws[10], &ws[14]);
		CHACHA20_QR(&ws[3], &ws[7], &ws[11], &ws[15]);

		//Diagonals
		CHACHA20_QR(&ws[0], &ws[5], &ws[10], &ws[15]);
		CHACHA20_QR(&ws[1], &ws[6], &ws[11], &ws[12]);
		CHACHA20_QR(&ws[2], &ws[7], &ws[8],  &ws[13]);
		CHACHA20_QR(&ws[3], &ws[4], &ws[9],  &ws[14]);
	}

	for (int i = 0; i < 16; i++) {
		ws[i] += state[i];
	}

    for (int i = 0; i < 16; i++) {
        output[i * 4]     = ws[i] & 0xFF;
        output[i * 4 + 1] = (ws[i] >> 8) & 0xFF;
        output[i * 4 + 2] = (ws[i] >> 16) & 0xFF;
        output[i * 4 + 3] = (ws[i] >> 24) & 0xFF;
    }
}

/* Implementation of the function to encrypt message using ChaCha20 */
static void CHACHA20_Encrypt(uint8_t *plaintext, uint8_t *ciphertext, uint32_t length, uint32_t key[8], uint32_t nonce[3], uint32_t counter) {
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2]
    };

    uint8_t keystream[64];
    for (uint32_t i = 0; i < length; i += 64) {
    	CHACHA20_Block(state, keystream);
        for (uint32_t j = 0; j < 64 && i + j < length; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        state[12]++;
    }
}

void delay(void)
{
    volatile uint32_t i = 0;
    for (i = 0; i < 800000; ++i)
    {
        __asm("NOP"); /* delay */
    }
}

/*!
 * @brief Main function
 */
int main(void)
{
    /* Define the init structure for the output LED pin*/
    gpio_pin_config_t led_config = {
        kGPIO_DigitalOutput,
        0,
    };

    /* Board pin, clock, debug console init */
    CLOCK_EnableClock(kCLOCK_GateGPIO3);

    BOARD_InitPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();

    /* Print a note to terminal. */
    PRINTF("\r\nCHACHA20 example \r\n");

    /* Init output LED GPIO. */
    GPIO_PinInit(BOARD_LED_GPIO, BOARD_LED_GPIO_PIN, &led_config);

    /* Example to encrypt using Chacha20 */
    uint8_t message[] = "Implementacion de ChaCha20 en MCXA153";
    uint32_t length = strlen((char *)message);

    /* Key 256 bits (32 bytes) */
    uint32_t key[8] = {0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20};

    /* Nonce 96 bits (3 values of 32 bits) */
    uint32_t nonce[3] = {0x00000000, 0x4a000000, 0x00000000};

    /* Counter */
    uint32_t contador = 0;

    /* CypherText and PlainText */
    uint8_t cypherText[length + 1], plainText[length + 1];
    memset(cypherText, 0, sizeof(cypherText));
    memset(plainText, 0, sizeof(plainText));

    /* Call function to encrypt */
    CHACHA20_Encrypt(message, cypherText, length, key, nonce, contador);
    PRINTF("\r\nCHACHA20 CypherText \r\n");
    for (uint32_t i = 0; i < length; i++) {
    	PRINTF("%02x ", cypherText[i]);
    }

    CHACHA20_Encrypt(cypherText, plainText, length, key, nonce, contador);
    PRINTF("\r\nCHACHA20 PlainText \r\n");
    PRINTF("%s", plainText);

    while (1)
    {
        delay();
        GPIO_PortToggle(BOARD_LED_GPIO, 1u << BOARD_LED_GPIO_PIN);
    }
}

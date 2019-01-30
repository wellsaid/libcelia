/*
 * config.h
 *
 *  Created on: Jan 30, 2019
 *      Author: wellsaid
 */

#ifndef LIBCELIA_CONFIG_H_
#define LIBCELIA_CONFIG_H_

/**
 * @brief Number of attributes in the universe
 *
 * The number of attributes that will be generated in the universe
 */
#define NUM_ATTR_CELIA 5

/**
 * @brief Length of each attribute in the universe
 *
 * The length (in characters, excluding final '\0') of each generated attribute
 */
#define ATTR_LEN_CELIA 2

/**
 * @brief length of the message to encrypt (bytes)
 */
#define MSG_LEN_CELIA 1

#define AES_LEN_CELIA ((MSG_LEN_CELIA+5)/16 + 1)*16

#endif /* LIBCELIA_CONFIG_H_ */

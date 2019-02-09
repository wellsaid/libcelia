/*
 * config.h
 *
 *  Created on: Jan 30, 2019
 *      Author: wellsaid
 */

#ifndef LIBCELIA_CONFIG_H_
#define LIBCELIA_CONFIG_H_

#include "project-conf.h"

/**
 * @brief Number of attributes in the universe
 *
 * The number of attributes that will be generated in the universe
 */
#ifdef CONF_NUM_ATTR
#define NUM_ATTR_CELIA CONF_NUM_ATTR
#else
#define NUM_ATTR_CELIA 5
#endif

/**
 * @brief Length of each attribute in the universe
 *
 * The length (in characters, excluding final '\0') of each generated attribute
 */
#ifdef CONF_ATTR_LEN
#define ATTR_LEN_CELIA CONF_ATTR_LEN
#else
#define ATTR_LEN_CELIA 2
#endif

/**
 * @brief length of the message to encrypt (bytes)
 */
#ifdef CONF_MSG_LEN
#define MSG_LEN_CELIA CONF_MSG_LEN
#else
#define MSG_LEN_CELIA 1
#endif

#define AES_LEN_CELIA ((MSG_LEN_CELIA+5)/16 + 1)*16

#endif /* LIBCELIA_CONFIG_H_ */

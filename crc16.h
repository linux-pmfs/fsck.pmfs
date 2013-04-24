/*
 *	crc16.h - CRC-16 routine
 *
 * Implements the standard CRC-16:
 *   Width 16
 *   Poly  0x8005 (x^16 + x^15 + x^2 + 1)
 *   Init  0
 *
 * Copyright (c) 2005 Ben Gardner <bgardner@wabtec.com>
 * Copyright 2013 Intel Corporation
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2. See the file COPYING for more details.
 */

#ifndef CRC16_H_
#define CRC16_H_

#include <stddef.h>
#include "types.h"

extern u16 crc16(u16 crc, const u8 *buffer, size_t len);

#endif /* CRC16_H_ */

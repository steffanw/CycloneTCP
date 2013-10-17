/**
 * @file endian.h
 * @brief Byte order conversion
 *
 * @section License
 *
 * Copyright (C) 2010-2013 Oryx Embedded. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded (www.oryx-embedded.com)
 * @version 1.3.8
 **/

#ifndef _ENDIAN_H
#define _ENDIAN_H

//Dependencies
#include "os.h"

//Load unaligned 16-bit integer (little-endian encoding)
#define LOAD16LE(p) (((uint8_t *)(p))[0] | (((uint8_t *)(p))[1] << 8))

//Load unaligned 16-bit integer (big-endian encoding)
#define LOAD16BE(p) ((((uint8_t *)(p))[0] << 8) | ((uint8_t *)(p))[1])

//Load unaligned 24-bit integer (little-endian encoding)
#define LOAD24LE(p) (((uint8_t *)(p))[0] | \
   (((uint8_t *)(p))[1] << 8) | (((uint8_t *)(p))[2] << 16))

//Load unaligned 24-bit integer (big-endian encoding)
#define LOAD24BE(p) ((((uint8_t *)(p))[0] << 16) | \
   (((uint8_t *)(p))[1] << 8) | ((uint8_t *)(p))[2])

//Load unaligned 32-bit integer (little-endian encoding)
#define LOAD32LE(p) (((uint8_t *)(p))[0] | (((uint8_t *)(p))[1] << 8) | \
   (((uint8_t *)(p))[2] << 16) | (((uint8_t *)(p))[3] << 24))

//Load unaligned 32-bit integer (big-endian encoding)
#define LOAD32BE(p) ((((uint8_t *)(p))[0] << 24) | (((uint8_t *)(p))[1] << 16) | \
   (((uint8_t *)(p))[2] << 8) | ((uint8_t *)(p))[3])

//Store unaligned 16-bit integer (little-endian encoding)
#define STORE16LE(a, p) \
   ((uint8_t *)(p))[0] = (a) & 0xFF, \
   ((uint8_t *)(p))[1] = ((a) >> 8) & 0xFF

//Store unaligned 32-bit integer (big-endian encoding)
#define STORE16BE(a, p) \
   ((uint8_t *)(p))[0] = ((a) >> 8) & 0xFF, \
   ((uint8_t *)(p))[1] = (a) & 0xFF

//Store unaligned 24-bit integer (little-endian encoding)
#define STORE24LE(a, p) \
   ((uint8_t *)(p))[0] = (a) & 0xFF, \
   ((uint8_t *)(p))[1] = ((a) >> 8) & 0xFF, \
   ((uint8_t *)(p))[2] = ((a) >> 16) & 0xFF

//Store unaligned 24-bit integer (big-endian encoding)
#define STORE24BE(a, p) \
   ((uint8_t *)(p))[0] = ((a) >> 16) & 0xFF, \
   ((uint8_t *)(p))[1] = ((a) >> 8) & 0xFF, \
   ((uint8_t *)(p))[2] = (a) & 0xFF

//Store unaligned 32-bit integer (little-endian encoding)
#define STORE32LE(a, p) \
   ((uint8_t *)(p))[0] = (a) & 0xFF, \
   ((uint8_t *)(p))[1] = ((a) >> 8) & 0xFF, \
   ((uint8_t *)(p))[2] = ((a) >> 16) & 0xFF, \
   ((uint8_t *)(p))[3] = ((a) >> 24) & 0xFF

//Store unaligned 32-bit integer (big-endian encoding)
#define STORE32BE(a, p) \
   ((uint8_t *)(p))[0] = ((a) >> 24) & 0xFF, \
   ((uint8_t *)(p))[1] = ((a) >> 16) & 0xFF, \
   ((uint8_t *)(p))[2] = ((a) >> 8) & 0xFF, \
   ((uint8_t *)(p))[3] = (a) & 0xFF

//Swap a 16-bit integer
#define SWAP16(x) ( \
   (((x) & 0x00FF) << 8) | \
   (((x) & 0xFF00) >> 8))

//Swap a 32-bit integer
#define SWAP32(x) ( \
   (((x) & 0x000000FFUL) << 24) | \
   (((x) & 0x0000FF00UL) << 8) | \
   (((x) & 0x00FF0000UL) >> 8) | \
   (((x) & 0xFF000000UL) >> 24))

//Swap a 64-bit integer
#define SWAP64(x) ( \
   (((x) & 0x00000000000000FFULL) << 56) | \
   (((x) & 0x000000000000FF00ULL) << 40) | \
   (((x) & 0x0000000000FF0000ULL) << 24) | \
   (((x) & 0x00000000FF000000ULL) << 8) | \
   (((x) & 0x000000FF00000000ULL) >> 8) | \
   (((x) & 0x0000FF0000000000ULL) >> 24) | \
   (((x) & 0x00FF000000000000ULL) >> 40) | \
   (((x) & 0xFF00000000000000ULL) >> 56))

//Big-endian machine?
#ifdef _BIG_ENDIAN

//Host byte order to network byte order
#define HTONS(value) (value)
#define HTONL(value) (value)
#define htons(value) (value)
#define htonl(value) (value)

//Network byte order to host byte order
#define NTOHS(value) (value)
#define NTOHL(value) (value)
#define ntohs(value) (value)
#define ntohl(value) (value)

//Host byte order to little-endian byte order
#define HTOLE16(value) SWAP16(value)
#define HTOLE32(value) SWAP32(value)
#define HTOLE64(value) SWAP64(value)
#define htole16(value) swap16(value)
#define htole32(value) swap32(value)
#define htole64(value) swap64(value)

//Little-endian byte order to host byte order
#define LETOH16(value) SWAP16(value)
#define LETOH32(value) SWAP32(value)
#define LETOH64(value) SWAP64(value)
#define letoh16(value) swap16(value)
#define letoh32(value) swap32(value)
#define letoh64(value) swap64(value)

//Host byte order to big-endian byte order
#define HTOBE16(value) (value)
#define HTOBE32(value) (value)
#define HTOBE64(value) (value)
#define htobe16(value) (value)
#define htobe32(value) (value)
#define htobe64(value) (value)

//Big-endian byte order to host byte order
#define BETOH16(value) (value)
#define BETOH32(value) (value)
#define BETOH64(value) (value)
#define betoh16(value) (value)
#define betoh32(value) (value)
#define betoh64(value) (value)

//Little-endian machine?
#else

//Host byte order to network byte order
#define HTONS(value) SWAP16(value)
#define HTONL(value) SWAP32(value)
#define htons(value) swap16(value)
#define htonl(value) swap32(value)

//Network byte order to host byte order
#define NTOHS(value) SWAP16(value)
#define NTOHL(value) SWAP32(value)
#define ntohs(value) swap16(value)
#define ntohl(value) swap32(value)

//Host byte order to little-endian byte order
#define HTOLE16(value) (value)
#define HTOLE32(value) (value)
#define HTOLE64(value) (value)
#define htole16(value) (value)
#define htole32(value) (value)
#define htole64(value) (value)

//Little-endian byte order to host byte order
#define LETOH16(value) (value)
#define LETOH32(value) (value)
#define LETOH64(value) (value)
#define letoh16(value) (value)
#define letoh32(value) (value)
#define letoh64(value) (value)

//Host byte order to big-endian byte order
#define HTOBE16(value) SWAP16(value)
#define HTOBE32(value) SWAP32(value)
#define HTOBE64(value) SWAP64(value)
#define htobe16(value) swap16(value)
#define htobe32(value) swap32(value)
#define htobe64(value) swap64(value)

//Big-endian byte order to host byte order
#define BETOH16(value) SWAP16(value)
#define BETOH32(value) SWAP32(value)
#define BETOH64(value) SWAP64(value)
#define betoh16(value) swap16(value)
#define betoh32(value) swap32(value)
#define betoh64(value) swap64(value)

#endif

//Byte order conversion functions
uint16_t swap16(uint16_t value);
uint32_t swap32(uint32_t value);
uint64_t swap64(uint64_t value);

#endif

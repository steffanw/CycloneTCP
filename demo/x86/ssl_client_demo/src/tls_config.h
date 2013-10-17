/**
 * @file tls_config.h
 * @brief CycloneSSL configuration file
 *
 * @section License
 *
 * Copyright (C) 2010-2013 Oryx Embedded. All rights reserved.
 *
 * This file is part of CycloneTCP Open.
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

#ifndef _TLS_CONFIG_H
#define _TLS_CONFIG_H

//Desired trace level (for debugging purposes)
#define TLS_TRACE_LEVEL TRACE_LEVEL_INFO

//Enable SSL/TLS support
#define TLS_SUPPORT ENABLED
//Client mode of operation
#define TLS_CLIENT_SUPPORT ENABLED
//Server mode of operation
#define TLS_SERVER_SUPPORT ENABLED

//Minimum version that can be negotiated
#define TLS_MIN_VERSION SSL_VERSION_3_0
//Maximum version that can be negotiated
#define TLS_MAX_VERSION TLS_VERSION_1_2

//Use BSD socket API
#define TLS_BSD_SOCKET_SUPPORT ENABLED

//Session resumption mechanism
#define TLS_SESSION_RESUME_SUPPORT ENABLED
//Lifetime of session cache entries
#define TLS_SESSION_CACHE_LIFETIME 3600000

//SNI (Server Name Indication) extension
#define TLS_SNI_SUPPORT ENABLED

//Maximum number of certificates the end entity can load
#define TLS_MAX_CERTIFICATES 3

//Maximum message length that can be handled by the higher-level protocol
#define TLS_MAX_PROTOCOL_DATA_LENGTH 32768

//RSA key exchange support
#define TLS_RSA_SUPPORT ENABLED
//DHE_RSA key exchange support
#define TLS_DHE_RSA_SUPPORT ENABLED
//DHE_DSS key exchange support
#define TLS_DHE_DSS_SUPPORT ENABLED
//DH_ANON key exchange support
#define TLS_DH_ANON_SUPPORT ENABLED

//RSA signature capability
#define TLS_RSA_SIGN_SUPPORT ENABLED
//DSA signature capability
#define TLS_DSA_SIGN_SUPPORT ENABLED

//Stream cipher support
#define TLS_STREAM_CIPHER_SUPPORT ENABLED
//CBC block cipher support
#define TLS_CBC_CIPHER_SUPPORT ENABLED
//CCM mode support
#define TLS_CCM_CIPHER_SUPPORT ENABLED
//GCM mode support
#define TLS_GCM_CIPHER_SUPPORT ENABLED

//RC4 cipher support
#define TLS_RC4_SUPPORT ENABLED
//IDEA cipher support
#define TLS_IDEA_SUPPORT ENABLED
//DES cipher support
#define TLS_DES_SUPPORT ENABLED
//Triple DES cipher support
#define TLS_3DES_SUPPORT ENABLED
//AES cipher support
#define TLS_AES_SUPPORT ENABLED
//Camellia cipher support
#define TLS_CAMELLIA_SUPPORT ENABLED
//SEED cipher support
#define TLS_SEED_SUPPORT ENABLED
//ARIA cipher support
#define TLS_ARIA_SUPPORT ENABLED

//MD5 hash support
#define TLS_MD5_SUPPORT ENABLED
//SHA-1 hash support
#define TLS_SHA1_SUPPORT ENABLED
//SHA-224 hash support
#define TLS_SHA224_SUPPORT ENABLED
//SHA-256 hash support
#define TLS_SHA256_SUPPORT ENABLED
//SHA-384 hash support
#define TLS_SHA384_SUPPORT ENABLED
//SHA-512 hash support
#define TLS_SHA512_SUPPORT ENABLED

#endif

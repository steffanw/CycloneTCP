/**
 * @file dns_client.h
 * @brief DNS client (Domain Name System)
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

#ifndef _DNS_CLIENT_H
#define _DNS_CLIENT_H

//Dependencies
#include "tcp_ip_stack.h"
#include "socket.h"

//Maximum number of retransmissions
#ifndef DNS_MAX_RETRIES
   #define DNS_MAX_RETRIES 3
#elif (DNS_MAX_RETRIES < 1)
   #error DNS_MAX_RETRIES parameter is invalid
#endif

//Default timeout value for DNS requests
#ifndef DNS_REQUEST_TIMEOUT
   #define DNS_REQUEST_TIMEOUT 5000
#elif (DNS_REQUEST_TIMEOUT < 1000)
   #error DNS_REQUEST_TIMEOUT parameter is invalid
#endif

//DNS port number
#define DNS_PORT 53
//Maximum size of DNS messages
#define DNS_MESSAGE_MAX_SIZE 512
//Maximum size of names
#define DNS_NAME_MAX_SIZE 255
//Maximum size of labels
#define DNS_LABEL_MAX_SIZE 63
//Label compression tag
#define DNS_COMPRESSION_TAG 0xC0

//Shortcut to a specified resource record
#define DNS_GET_RESOURCE_RECORD(message, offset) PTR_OFFSET(message, offset)

typedef enum
{
   DNS_FLAG_QR     = 0x0080,
   DNS_OPCODE_MASK = 0x0078,
   DNS_FLAG_AA     = 0x0004,
   DNS_FLAG_TC     = 0x0002,
   DNS_FLAG_RD     = 0x0001,
   DNS_FLAG_RA     = 0x8000,
   DNS_RCODE_MASK  = 0x0F00
} DnsFlags;

typedef enum
{
   DNS_OPCODE_QUERY         = (0 << 3),
   DNS_OPCODE_INVERSE_QUERY = (1 << 3),
   DNS_OPCODE_STATUS        = (2 << 3),
   DNS_OPCODE_NOTIFY        = (4 << 3),
   DNS_OPCODE_UPDATE        = (5 << 3)
} DnsOpcode;

typedef enum
{
   DNS_RCODE_NO_ERROR        = (0 << 8),
   DNS_RCODE_FORMAT_ERROR    = (1 << 8),
   DNS_RCODE_SERVER_FAILURE  = (2 << 8),
   DNS_RCODE_NAME_ERROR      = (3 << 8),
   DNS_RCODE_NOT_IMPLEMENTED = (4 << 8),
   DNS_RCODE_QUERY_REFUSED   = (5 << 8)
}DnsReturnCode;

typedef enum
{
   DNS_RR_TYPE_A     = 1,
   DNS_RR_TYPE_NS    = 2,
   DNS_RR_TYPE_CNAME = 5,
   DNS_RR_TYPE_PTR   = 12,
   DNS_RR_TYPE_HINFO = 13,
   DNS_RR_TYPE_MX    = 15,
   DNS_RR_TYPE_AAAA  = 28,
   DNS_RR_TYPE_AXFR  = 252,
   DNS_RR_TYPE_ANY   = 255
} DnsResourceRecordType;

typedef enum
{
   DNS_RR_CLASS_IN = 1,
   DNS_RR_CLASS_CH = 3,
   DNS_RR_CLASS_HS = 4
} DnsResourceRecordClass;


#if (defined(__GNUC__) || defined(_WIN32))
   #define __packed
   #pragma pack(push, 1)
#endif


typedef __packed struct
{
   uint16_t identifier;            //0-1
   uint16_t flags;                 //2-3
   uint16_t questionCount;         //4-5
   uint16_t answerRecordCount;     //6-7
   uint16_t authorityRecordCount;  //8-9
   uint16_t additionalRecordCount; //10-11
   uint8_t questions[];            //12
} DnsHeader;

typedef __packed struct
{
   uint16_t queryType;
   uint16_t queryClass;
} DnsQuestion;

typedef __packed struct
{
   uint16_t type;       //0-1
   uint16_t class;      //2-3
   uint32_t timeToLive; //4-7
   uint16_t dataLength; //8-9
   uint8_t data[];      //10
} DnsResourceRecord;


#if (defined(__GNUC__) || defined(_WIN32))
   #undef __packed
   #pragma pack(pop)
#endif


error_t dnsResolve(NetInterface *interface, const char_t *name, IpAddr *ipAddr);

error_t dnsSendQuery(Socket *socket, DnsHeader *dnsMessage, uint16_t identifier, const char_t *name);
error_t dnsParseResponse(DnsHeader *dnsMessage, size_t length, uint16_t identifier, IpAddr *ipAddr);

size_t dnsEncodeName(const char_t *src, uint8_t *dest);
size_t dnsDecodeName(DnsHeader *dnsMessage, size_t length, size_t pos, char_t *dest);

#endif

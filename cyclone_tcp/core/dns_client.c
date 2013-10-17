/**
 * @file dns_client.c
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

//Switch to the appropriate trace level
#define TRACE_LEVEL DNS_TRACE_LEVEL

//Dependencies
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "tcp_ip_stack.h"
#include "dns_client.h"
#include "socket.h"
#include "ip.h"
#include "ipv4.h"
#include "debug.h"


/**
 * @brief Resolve a host name into an IP address
 * @param[in] interface Underlying network interface (optional parameter)
 * @param[in] name Name of the host to resolve
 * @param[out] ipAddr IP address of the specified host
 * @return Error code
 **/

error_t dnsResolve(NetInterface *interface, const char_t *name, IpAddr *ipAddr)
{
   error_t error;
   uint_t i;
   size_t length;
   uint16_t identifier;
   IpAddr serverIpAddr;
   Socket *socket;
   DnsHeader *dnsMessage;

   //Debug message
   TRACE_INFO("Trying to resolve %s...\r\n", name);

   //Use default network interface?
   if(!interface)
      interface = tcpIpStackGetDefaultInterface();

   //Allocate a memory buffer to hold DNS messages
   dnsMessage = memPoolAlloc(DNS_MESSAGE_MAX_SIZE);
   //Failed to allocate memory?
   if(!dnsMessage)
      return ERROR_OUT_OF_MEMORY;

   //Open a UDP socket
   socket = socketOpen(SOCKET_TYPE_DGRAM, SOCKET_PROTOCOL_UDP);

   //Failed to open socket?
   if(!socket)
   {
      //Free previously allocated memory
      memPoolFree(dnsMessage);
      //Return status code
      return ERROR_OPEN_FAILED;
   }

#if (IPV4_SUPPORT == ENABLED)
   //IP address of the DNS server
   serverIpAddr.length = sizeof(Ipv4Addr);
   serverIpAddr.ipv4Addr = interface->ipv4Config.dnsServer[0];
#elif (IPV6_SUPPORT == ENABLED)
   //IP address of the DNS server
   serverIpAddr.length = sizeof(Ipv6Addr);
   serverIpAddr.ipv6Addr = interface->ipv6Config.dnsServer[0];
#endif

   //Associate the socket with the relevant interface
   error = socketBindToInterface(socket, interface);

   //Any error to report?
   if(error)
   {
      //Free previously allocated memory
      memPoolFree(dnsMessage);
      //Close socket
      socketClose(socket);
      //Return status code
      return error;
   }

   //Connect the newly created socket to the primary DNS server
   error = socketConnect(socket, &serverIpAddr, DNS_PORT);

   //Failed to connect?
   if(error)
   {
      //Free previously allocated memory
      memPoolFree(dnsMessage);
      //Close socket
      socketClose(socket);
      //Return status code
      return error;
   }

   //An identifier is used by the client to match replies
   //with corresponding requests
   identifier = rand();

   //Try to retransmit the DNS message if the previous query timed out
   for(i = 0; i < DNS_MAX_RETRIES; i++)
   {
      //Send DNS query message
      error = dnsSendQuery(socket, dnsMessage, identifier, name);
      //Failed to send message ?
      if(error) break;

      //Adjust receive timeout
      error = socketSetTimeout(socket, DNS_REQUEST_TIMEOUT);
      //Any error to report?
      if(error) break;

      //Wait for the server response
      error = socketReceive(socket, dnsMessage, DNS_MESSAGE_MAX_SIZE, &length, 0);

      //Any response from the specified DNS server?
      if(!error)
      {
         //Parse DNS response
         error = dnsParseResponse(dnsMessage, length, identifier, ipAddr);
         //DNS response successfully decoded?
         if(!error) break;
      }
   }

   //The maximum number of retransmissions has been reached?
   if(i >= DNS_MAX_RETRIES)
      error = ERROR_TIMEOUT;

   //Free previously allocated memory
   memPoolFree(dnsMessage);
   //Close socket
   socketClose(socket);

   //Debug message
   if(!error)
   {
      //Name resolution succeeds
      TRACE_INFO("Host name resolved to %s...\r\n", ipAddrToString(ipAddr, NULL));
   }
   else
   {
      //Report an error
      TRACE_ERROR("DNS resolution failed!\r\n");
   }

   //Return status code
   return error;
}


/**
 * @brief Send a DNS query message
 * @param[in] socket Handle referencing a socket
 * @param[in] dnsMessage Buffer needed to format the DNS query message
 * @param[in] identifier Identifier used to match queries and responses
 * @param[out] name Host name to resolve
 * @return Error code
 **/

error_t dnsSendQuery(Socket *socket, DnsHeader *dnsMessage, uint16_t identifier, const char_t *name)
{
   size_t length;
   DnsQuestion *dnsQuestion;

   //Debug message
   TRACE_INFO("Sending DNS query message...\r\n");

   //Format DNS query message
   dnsMessage->identifier = identifier;
   dnsMessage->flags = DNS_OPCODE_QUERY | DNS_FLAG_RD;
   dnsMessage->questionCount = HTONS(1);
   dnsMessage->answerRecordCount = 0;
   dnsMessage->authorityRecordCount = 0;
   dnsMessage->additionalRecordCount = 0;

   //Query name
   length = dnsEncodeName(name, dnsMessage->questions);

   //Query type and query class
   dnsQuestion = (DnsQuestion *) (dnsMessage->questions + length);
   dnsQuestion->queryType = HTONS(DNS_RR_TYPE_A);
   dnsQuestion->queryClass = HTONS(DNS_RR_CLASS_IN);

   //Length of the complete message
   length += sizeof(DnsHeader) + sizeof(DnsQuestion);

   //Send DNS query message
   return socketSend(socket, dnsMessage, length, NULL, 0);
}


/**
 * @brief Parse a DNS response message and retrieve host address
 * @param[in] dnsMessage DNS response message to parse
 * @param[in] length Length of the DNS message
 * @param[in] identifier Identifier used to match queries and responses
 * @param[out] ipAddr Host IP address
 * @return Error code
 **/

error_t dnsParseResponse(DnsHeader *dnsMessage, size_t length, uint16_t identifier, IpAddr *ipAddr)
{
   char_t *name;
   uint_t i;
   size_t pos;
   Ipv4Addr ipv4Addr;
   DnsQuestion *dnsQuestion;
   DnsResourceRecord *dnsResourceRecord;

   //Clear host address
   memset(ipAddr, 0, sizeof(IpAddr));

   //Ensure the DNS header is valid
   if(length < sizeof(DnsHeader))
      return ERROR_INVALID_HEADER;
   //Compare identifier against expected one
   if(dnsMessage->identifier != identifier)
      return ERROR_WRONG_IDENTIFIER;
   //Check message type
   if(!(dnsMessage->flags & DNS_FLAG_QR))
      return ERROR_INVALID_HEADER;
   //Make sure recursion is available
   if(!(dnsMessage->flags & DNS_FLAG_RA))
      return ERROR_INVALID_HEADER;
   //Check return code
   if(dnsMessage->flags & DNS_RCODE_MASK)
      return ERROR_FAILURE;

   //Debug message
   TRACE_DEBUG("DNS response message received (%u bytes)...\r\n", length);

   //Allocate memory buffer to hold the decoded name
   name = memPoolAlloc(DNS_NAME_MAX_SIZE);
   //Failed to allocate memory
   if(!name) return ERROR_OUT_OF_MEMORY;

   //Debug message
   TRACE_DEBUG("%u questions found...\r\n", ntohs(dnsMessage->questionCount));
   //Point to the first question
   pos = sizeof(DnsHeader);

   //Parse questions
   for(i = 0; i < ntohs(dnsMessage->questionCount); i++)
   {
      //Decode domain name
      pos = dnsDecodeName(dnsMessage, length, pos, name);
      //Name decoding failed?
      if(!pos)
      {
         //Free previously allocated memory
         memPoolFree(name);
         //Report an error
         return ERROR_INVALID_NAME;
      }
      //Point to the associated resource record
      dnsQuestion = DNS_GET_RESOURCE_RECORD(dnsMessage, pos);
      //Debug message
      TRACE_DEBUG("  name = %s\r\n", name);
      TRACE_DEBUG("    queryType = %u\r\n", ntohs(dnsQuestion->queryType));
      TRACE_DEBUG("    queryClass = %u\r\n", ntohs(dnsQuestion->queryClass));
      //Point to the next question
      pos += sizeof(DnsQuestion);
   }

   //Debug message
   TRACE_INFO("%u answer RRs found...\r\n", ntohs(dnsMessage->answerRecordCount));

   //Parse answer resource records
   for(i = 0; i < ntohs(dnsMessage->answerRecordCount); i++)
   {
      //Decode domain name
      pos = dnsDecodeName(dnsMessage, length, pos, name);
      //Name decoding failed?
      if(!pos)
      {
         //Free previously allocated memory
         memPoolFree(name);
         //Report an error
         return ERROR_INVALID_NAME;
      }
      //Point to the associated resource record
      dnsResourceRecord = DNS_GET_RESOURCE_RECORD(dnsMessage, pos);
      //Debug message
      TRACE_DEBUG("  name = %s\r\n", name);
      TRACE_DEBUG("    type = %u\r\n", ntohs(dnsResourceRecord->type));
      TRACE_DEBUG("    class = %u\r\n", ntohs(dnsResourceRecord->class));
      TRACE_DEBUG("    ttl = %u\r\n", ntohl(dnsResourceRecord->timeToLive));
      TRACE_DEBUG("    dataLength = %u\r\n", ntohs(dnsResourceRecord->dataLength));
      //Check the type of the resource record
      switch(ntohs(dnsResourceRecord->type))
      {
      //IPv4 address record found?
      case DNS_RR_TYPE_A:
         //Verify the length of the data field
         if(ntohs(dnsResourceRecord->dataLength) != sizeof(Ipv4Addr))
            break;
         //Copy the IP address
         ipv4CopyAddr(&ipv4Addr, dnsResourceRecord->data);
         //Save the first IP address found in resource records
         if(!ipAddr->length)
         {
            ipAddr->length = sizeof(Ipv4Addr);
            ipAddr->ipv4Addr = ipv4Addr;
         }
         //Debug message
         TRACE_DEBUG("    data = %s\r\n", ipv4AddrToString(ipv4Addr, NULL));
         break;
      //IPv6 address record found?
      /*case DNS_RR_TYPE_AAAA:
         //Verify the length of the data field
         if(ntohs(dnsResourceRecord->dataLength) != sizeof(Ipv6Addr))
            break;
         //Copy the IP address
         //ipv4CopyAddr(&ipv4Addr, dnsResourceRecord->data);
         //Save the first IP address found in resource records
         if(!ipAddr->length)
         {
            ipAddr->length = sizeof(Ipv6Addr);
            ipv6CopyAddr(&ipAddr->ipv6Addr, dnsResourceRecord->data);
         }
         //Debug message
         //TRACE_DEBUG("    data = %s\r\n", ipv4AddrToString(ipv4Addr, NULL));
         break;*/
      //Name server record found?
      case DNS_RR_TYPE_NS:
      //Canonical name record found?
      case DNS_RR_TYPE_CNAME:
      //Pointer record?
      case DNS_RR_TYPE_PTR:
         //Decode the canonical name
         dnsDecodeName(dnsMessage, length, pos + sizeof(DnsResourceRecord), name);
         //Debug message
         TRACE_DEBUG("    data = %s\r\n", name);
         break;
      //Unknown record
      default:
         break;
      }
      //Point to the next resource record
      pos += sizeof(DnsResourceRecord) + ntohs(dnsResourceRecord->dataLength);
   }

   //Debug message
   TRACE_INFO("%u authority RRs found...\r\n", ntohs(dnsMessage->authorityRecordCount));
   TRACE_INFO("%u additional RRs found...\r\n", ntohs(dnsMessage->additionalRecordCount));

   //Free previously allocated memory
   memPoolFree(name);
   //DNS response successfully decoded
   return NO_ERROR;
}


/**
 * @brief Encode a domain name using the DNS name notation
 * @param[in] src Pointer to the domain name to encode
 * @param[out] dest Pointer to the encoded domain name
 * @return Length of the encoded domain name
 **/

size_t dnsEncodeName(const char_t *src, uint8_t *dest)
{
   uint_t i = 0;
   size_t length = 0;

   //Parse input name
   while(1)
   {
      //End of string detected?
      if(src[i] == '\0')
      {
         //Check label length
         if(i < 1 || i > DNS_LABEL_MAX_SIZE)
            return 0;
         //Save label length
         dest[0] = i;
         dest[i + 1] = 0;
         //Adjust the length of the resulting string
         length += i + 2;
         //Stop parsing the input string
         return length;
      }
      //Separator detected?
      else if(src[i] == '.')
      {
         //Check label length
         if(i < 1 || i > DNS_LABEL_MAX_SIZE)
            return 0;
         //Save label length
         dest[0] = i;
         //Adjust the length of the resulting string
         length += i + 1;
         //Prepare to decode the next label
         src += i + 1;
         dest += i + 1;
         i = 0;
      }
      //Valid character detected?
      else if(isalnum((uint8_t) src[i]) || src[i] == '-')
      {
         //Copy current character
         dest[i + 1] = src[i];
         //Point to the next character
         i++;
      }
      //Invalid character detected?
      else
      {
         //Stop parsing the input string
         return 0;
      }
   }
}


/**
 * @brief Decode a domain name that uses the DNS name encoding
 * @param[in] dnsMessage Pointer to the DNS message
 * @param[in] length Length of the DNS message
 * @param[in] pos Offset of the name to decode
 * @param[out] dest Pointer to the decoded name
 * @return The position of the resource record that is immediately following the domain name
 **/

size_t dnsDecodeName(DnsHeader *dnsMessage, size_t length, size_t pos, char_t *dest)
{
   size_t pointer;
   size_t labelLength;

   //Cast the input DNS message to byte array
   uint8_t *src = (uint8_t *) dnsMessage;

   //Parse encoded domain name
   while(pos < length)
   {
      //End marker found?
      if(src[pos] == 0)
      {
         //Properly terminate the string
         *dest = '\0';
         //Return the position of the resource record that
         //is immediately following the domain name
         return (pos + 1);
      }
      //Compression tag found?
      if(src[pos] >= DNS_COMPRESSION_TAG)
      {
         //Read the most significant byte of the pointer
         pointer = (src[pos] & ~DNS_COMPRESSION_TAG) << 8;
         //Read the least significant byte of the pointer
         pointer |= src[pos + 1];
         //Decode the remaining part the domain name
         if(!dnsDecodeName(dnsMessage, length, pointer, dest))
         {
            //Domain name decoding failed
            return 0;
         }
         //Return the position of the resource record that
         //is immediately following the domain name
         return (pos + 2);
      }
      //Valid label length?
      else if(src[pos] < DNS_LABEL_MAX_SIZE)
      {
         //Get the length of the following label
         labelLength = src[pos++];
         //Parse the label
         while(labelLength--)
            *(dest++) = src[pos++];
         //Append a separator
         *(dest++) = '.';
      }
      //Invalid label length?
      else
      {
         //Properly terminate the string
         *dest = '\0';
         //Domain name decoding failed
         return 0;
      }
   }

   //Domain name decoding failed
   return 0;
}

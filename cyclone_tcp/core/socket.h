/**
 * @file socket.h
 * @brief Socket API
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

#ifndef _SOCKET_H
#define _SOCKET_H

//Forward declaration of Socket structure
struct _Socket;
#define Socket struct _Socket

//Dependencies
#include "tcp_ip_stack.h"
#include "ip.h"
#include "tcp.h"

//Number of sockets that can be opened simultaneously
#ifndef SOCKET_MAX_COUNT
   #define SOCKET_MAX_COUNT 16
#elif (SOCKET_MAX_COUNT < 1)
   #error SOCKET_MAX_COUNT parameter is invalid
#endif

//Dynamic port range (lower limit)
#ifndef SOCKET_EPHEMERAL_PORT_MIN
   #define SOCKET_EPHEMERAL_PORT_MIN 49152
#elif (SOCKET_EPHEMERAL_PORT_MIN < 1024)
   #error SOCKET_EPHEMERAL_PORT_MIN parameter is invalid
#endif

//Dynamic port range (upper limit)
#ifndef SOCKET_EPHEMERAL_PORT_MAX
   #define SOCKET_EPHEMERAL_PORT_MAX 65535
#elif (SOCKET_EPHEMERAL_PORT_MAX <= SOCKET_EPHEMERAL_PORT_MIN || SOCKET_EPHEMERAL_PORT_MAX > 65535)
   #error SOCKET_EPHEMERAL_PORT_MAX parameter is invalid
#endif


/**
 * @brief Socket types
 **/

typedef enum
{
   SOCKET_TYPE_UNUSED = 0,
   SOCKET_TYPE_STREAM = 1,
   SOCKET_TYPE_DGRAM  = 2,
   SOCKET_TYPE_RAW    = 3
} SocketType;


/**
 * @brief Socket protocols
 **/

typedef enum
{
   SOCKET_PROTOCOL_ICMP   = 1,
   SOCKET_PROTOCOL_IGMP   = 2,
   SOCKET_PROTOCOL_TCP    = 6,
   SOCKET_PROTOCOL_UDP    = 17,
   SOCKET_PROTOCOL_ICMPV6 = 58
} SocketProtocol;


/**
 * @brief Flags used by I/O functions
 **/

typedef enum
{
   SOCKET_FLAG_PEEK       = 0x0200,
   SOCKET_FLAG_DONT_ROUTE = 0x0400,
   SOCKET_FLAG_WAIT_ALL   = 0x0800,
   SOCKET_FLAG_BREAK_CHAR = 0x1000,
   SOCKET_FLAG_BREAK_CRLF = 0x100A,
   SOCKET_FLAG_WAIT_ACK   = 0x2000
} SocketFlags;


//The SOCKET_FLAG_BREAK macro causes the I/O functions to stop reading
//data whenever the specified break character is encountered
#define SOCKET_FLAG_BREAK(c) (SOCKET_FLAG_BREAK_CHAR | LSB(c))


/**
 * @brief Flags used by shutdown function
 **/

typedef enum
{
   SOCKET_SD_RECEIVE = 0,
   SOCKET_SD_SEND    = 1,
   SOCKET_SD_BOTH    = 2
} SocketShutdownFlags;


/**
 * @brief Socket events
 **/

typedef enum
{
   SOCKET_EVENT_TIMEOUT      = 0x0000,
   SOCKET_EVENT_CONNECTED    = 0x0001,
   SOCKET_EVENT_CLOSED       = 0x0002,
   SOCKET_EVENT_TX_READY     = 0x0004,
   SOCKET_EVENT_TX_COMPLETE  = 0x0008,
   SOCKET_EVENT_TX_SHUTDOWN  = 0x0010,
   SOCKET_EVENT_RX_READY     = 0x0020,
   SOCKET_EVENT_RX_SHUTDOWN  = 0x0040,
   SOCKET_EVENT_LINK_UP      = 0x0080,
   SOCKET_EVENT_LINK_DOWN    = 0x0100
} SocketEvent;


/**
 * @brief Receive queue item
 **/

typedef struct _SocketQueueItem
{
   struct _SocketQueueItem *next;
   IpAddr remoteIpAddr;
   uint16_t remotePort;
   ChunkedBuffer *buffer;
   size_t offset;
} SocketQueueItem;


/**
 * @brief Structure describing a socket
 **/

struct _Socket
{
   uint_t descriptor;
   uint_t type;
   uint8_t protocol;
   NetInterface *interface;
   IpAddr localIpAddr;
   uint16_t localPort;
   IpAddr remoteIpAddr;
   uint16_t remotePort;
   time_t timeout;
   error_t lastError;
   OsEvent *event;
   uint_t eventMask;
   uint_t eventFlags;
   OsEvent *userEvent;
   //TCP specific variables
   TcpControlBlock;
   //UDP specific variables
   SocketQueueItem *receiveQueue;
};


/**
 * @brief Structure describing socket events
 **/

typedef struct
{
   Socket *socket;    ///<Handle to a socket to monitor
   uint_t eventMask;  ///<Requested events
   uint_t eventFlags; ///<Returned events
} SocketEventDesc;


//Global variables
extern OsMutex *socketMutex;
extern Socket socketTable[SOCKET_MAX_COUNT];

//Socket related functions
error_t socketInit(void);

Socket *socketOpen(uint_t type, uint8_t protocol);

error_t socketSetTimeout(Socket *socket, time_t timeout);
error_t socketBindToInterface(Socket *socket, NetInterface *interface);
error_t socketBind(Socket *socket, const IpAddr *localIpAddr, uint16_t localPort);
error_t socketConnect(Socket *socket, const IpAddr *remoteIpAddr, uint16_t remotePort);
error_t socketListen(Socket *socket);
Socket *socketAccept(Socket *socket, IpAddr *clientIpAddr, uint16_t *clientPort);

error_t socketSend(Socket *socket, const void *data,
   size_t length, size_t *written, uint_t flags);

error_t socketSendTo(Socket *socket, const IpAddr *remoteIpAddr, uint16_t remotePort,
   const void *data, size_t length, size_t *written, uint_t flags);

error_t socketReceive(Socket *socket, void *data,
   size_t size, size_t *received, uint_t flags);

error_t socketReceiveFrom(Socket *socket, IpAddr *remoteIpAddr,
   uint16_t *remotePort, void *data, size_t size, size_t *received, uint_t flags);

error_t socketGetLocalAddr(Socket *socket, IpAddr *localIpAddr, uint16_t *localPort);
error_t socketGetRemoteAddr(Socket *socket, IpAddr *remoteIpAddr, uint16_t *remotePort);

error_t socketShutdown(Socket *socket, uint_t how);
void socketClose(Socket *socket);

error_t socketPoll(SocketEventDesc *eventDesc, uint_t size, OsEvent *extEvent, time_t timeout);
error_t socketRegisterEvents(Socket *socket, OsEvent *event, uint_t eventMask);
error_t socketUnregisterEvents(Socket *socket);
error_t socketGetEvents(Socket *socket, uint_t *eventFlags);

error_t socketError(Socket *socket, error_t error);
error_t socketGetLastError(Socket *socket);

error_t getHostByName(NetInterface *interface, const char_t *name,
   IpAddr *ipAddrList, size_t maxEntries, size_t *numEntries, uint_t flags);

#endif

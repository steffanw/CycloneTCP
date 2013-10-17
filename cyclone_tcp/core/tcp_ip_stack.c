/**
 * @file tcp_ip_stack.c
 * @brief TCP/IP stack
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
#define TRACE_LEVEL ETH_TRACE_LEVEL

//Dependencies
#include "tcp_ip_stack.h"
#include "socket.h"
#include "tcp_timer.h"
#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"
#include "igmp.h"
#include "ipv6.h"
#include "mld.h"
#include "ndp.h"
#include "debug.h"

//Global variables
NetInterface netInterface[NET_INTERFACE_COUNT];


/**
 * @brief TCP/IP stack initialization
 * @return Error code
 **/

error_t tcpIpStackInit(void)
{
   error_t error;
   uint_t i;
   OsTask *task;

   //Memory pool initialization
   error = memPoolInit();
   //Any error to report?
   if(error) return error;

   //Clear configuration data for each interface
   memset(netInterface, 0, sizeof(netInterface));

   //Loop through network interfaces
   for(i = 0; i < NET_INTERFACE_COUNT; i++)
   {
      //Default interface identifier
      netInterface[i].identifier = i;
      //Default name
      sprintf(netInterface[i].name, "eth%u", i);
   }

   //Socket related initialization
   error = socketInit();
   //Any error to report?
   if(error) return error;

   //Create task to handle periodic operations
   task = osTaskCreate("TCP/IP Stack (Tick)", tcpIpStackTickTask,
      NULL, TCP_IP_TICK_STACK_SIZE, TCP_IP_TICK_PRIORITY);
   //Unable to create the task?
   if(task == OS_INVALID_HANDLE)
      return ERROR_OUT_OF_RESOURCES;

   //The handle can be used for further referencing
   for(i = 0; i < NET_INTERFACE_COUNT; i++)
      netInterface[i].tickTask = task;

   //Return status code
   return error;
}


/**
 * @brief Configure network interface
 * @param[in] interface Network interface to configure
 * @return Error code
 **/

error_t tcpIpStackConfigInterface(NetInterface *interface)
{
   error_t error;

//IPv6 specific variables
#if (IPV6_SUPPORT == ENABLED)
   Ipv6Addr solicitedNodeAddr;
#endif

   //Disable Ethernet controller interrupts
   interface->nicDriver->disableIrq(interface);

   //Start of exception handling block
   do
   {
      //Receive notifications when the transmitter is ready to send
      interface->nicTxEvent = osEventCreate(FALSE, FALSE);
      //Out of resources?
      if(interface->nicTxEvent == OS_INVALID_HANDLE)
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         //Stop immediately
         break;
      }

      //Receive notifications when a Ethernet frame has been received,
      //or the link status has changed
      interface->nicRxEvent = osEventCreate(FALSE, FALSE);
      //Out of resources?
      if(interface->nicRxEvent == OS_INVALID_HANDLE)
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         //Stop immediately
         break;
      }

      //Create a mutex to prevent simultaneous access to the NIC driver
      interface->nicDriverMutex = osMutexCreate(FALSE);
      //Out of resources?
      if(interface->nicDriverMutex == OS_INVALID_HANDLE)
      {
         //Report an error
         error = ERROR_OUT_OF_RESOURCES;
         //Stop immediately
         break;
      }

      //Ethernet controller configuration
      error = interface->nicDriver->init(interface);
      //Any error to report?
      if(error) break;

      //Ethernet related initialization
      error = ethInit(interface);
      //Any error to report?
      if(error) break;

//IPv4 specific initialization
#if (IPV4_SUPPORT == ENABLED)
      //Network layer initialization
      error = ipv4Init(interface);
      //Any error to report?
      if(error) break;

      //ARP cache initialization
      error = arpInit(interface);
      //Any error to report?
      if(error) break;

#if (IGMP_SUPPORT == ENABLED)
      //IGMP related initialization
      error = igmpInit(interface);
      //Any error to report?
      if(error) break;

      //Join the all-systems group
      error = ipv4JoinMulticastGroup(interface, IGMP_ALL_SYSTEMS_ADDR);
      //Any error to report?
      if(error) break;
#endif
#endif

//IPv6 specific initialization
#if (IPV6_SUPPORT == ENABLED)
      //Network layer initialization
      error = ipv6Init(interface);
      //Any error to report?
      if(error) break;

      //Neighbor cache initialization
      error = ndpInit(interface);
      //Any error to report?
      if(error) break;

#if (MLD_SUPPORT == ENABLED)
      ///MLD related initialization
      error = mldInit(interface);
      //Any error to report?
      if(error) break;
#endif
      //Join the All-Nodes multicast address
      error = ipv6JoinMulticastGroup(interface, &IPV6_LINK_LOCAL_ALL_NODES_ADDR);
      //Any error to report?
      if(error) break;

      //Form the Solicited-Node address for the link-local address
      error = ipv6ComputeSolicitedNodeAddr(&interface->ipv6Config.linkLocalAddr, &solicitedNodeAddr);
      //Any error to report?
      if(error) break;

      //Join the Solicited-Node multicast group for each assigned address
      error = ipv6JoinMulticastGroup(interface, &solicitedNodeAddr);
      //Any error to report?
      if(error) break;
#endif

      //Create a task to process incoming frames
      interface->rxTask = osTaskCreate("TCP/IP Stack (RX)", tcpIpStackRxTask,
         interface, TCP_IP_RX_STACK_SIZE, TCP_IP_RX_PRIORITY);

      //Unable to create the task?
      if(interface->rxTask == OS_INVALID_HANDLE)
         error = ERROR_OUT_OF_RESOURCES;

      //End of exception handling block
   } while(0);

   //Check whether the interface is fully configured
   if(!error)
   {
      //Successful interface configuration
      interface->configured = TRUE;
      //Interrupts can be safely enabled
      interface->nicDriver->enableIrq(interface);
   }
   else
   {
      //Clean up side effects before returning
      osEventClose(interface->nicTxEvent);
      osEventClose(interface->nicRxEvent);
      osMutexClose(interface->nicDriverMutex);
   }

   //Return status code
   return error;
}


/**
 * @brief Task responsible for handling periodic operations
 **/

void tcpIpStackTickTask(void *param)
{
   uint_t i;

   //Initialize prescalers
   uint_t nicTickPrescaler = 0;
#if (IPV4_SUPPORT == ENABLED)
   uint_t arpTickPrescaler = 0;
#endif
#if (IPV4_SUPPORT == ENABLED && IPV4_FRAG_SUPPORT == ENABLED)
   uint_t ipv4FragTickPrescaler = 0;
#endif
#if (IPV4_SUPPORT == ENABLED && IGMP_SUPPORT == ENABLED)
   uint_t igmpTickPrescaler = 0;
#endif
#if (IPV6_SUPPORT == ENABLED)
   uint_t ndpTickPrescaler = 0;
#endif
#if (IPV6_SUPPORT == ENABLED && IPV6_FRAG_SUPPORT == ENABLED)
   uint_t ipv6FragTickPrescaler = 0;
#endif
#if (IPV6_SUPPORT == ENABLED && MLD_SUPPORT == ENABLED)
   uint_t mldTickPrescaler = 0;
#endif
#if (TCP_SUPPORT == ENABLED)
   uint_t tcpTickPrescaler = 0;
#endif

   //Main loop
   while(1)
   {
      //Wait for the TCP/IP stack tick interval
      osDelay(TCP_IP_TICK_INTERVAL);

      //Update prescaler
      nicTickPrescaler += TCP_IP_TICK_INTERVAL;

      //Handle periodic operations such as polling the link state
      if(nicTickPrescaler >= NIC_TICK_INTERVAL)
      {
         //Loop through network interfaces
         for(i = 0; i < NET_INTERFACE_COUNT; i++)
         {
            //Make sure the interface has been properly configured
            if(netInterface[i].configured)
               nicTick(&netInterface[i]);
         }

         //Clear prescaler
         nicTickPrescaler = 0;
      }

#if (IPV4_SUPPORT == ENABLED)
      //Update prescaler
      arpTickPrescaler += TCP_IP_TICK_INTERVAL;

      //Manage ARP cache
      if(arpTickPrescaler >= ARP_TICK_INTERVAL)
      {
         //Loop through network interfaces
         for(i = 0; i < NET_INTERFACE_COUNT; i++)
         {
            //Make sure the interface has been properly configured
            if(netInterface[i].configured)
               arpTick(&netInterface[i]);
         }

         //Clear prescaler
         arpTickPrescaler = 0;
      }
#endif

#if (IPV4_SUPPORT == ENABLED && IPV4_FRAG_SUPPORT == ENABLED)
      //Update prescaler
      ipv4FragTickPrescaler += TCP_IP_TICK_INTERVAL;

      //Handle IPv4 fragment reassembly timeout
      if(ipv4FragTickPrescaler >= IPV4_FRAG_TICK_INTERVAL)
      {
         //Loop through network interfaces
         for(i = 0; i < NET_INTERFACE_COUNT; i++)
         {
            //Make sure the interface has been properly configured
            if(netInterface[i].configured)
               ipv4FragTick(&netInterface[i]);
         }

         //Clear prescaler
         ipv4FragTickPrescaler = 0;
      }
#endif

#if (IPV4_SUPPORT == ENABLED && IGMP_SUPPORT == ENABLED)
      //Update prescaler
      igmpTickPrescaler += TCP_IP_TICK_INTERVAL;

      //Handle IGMP related timers
      if(igmpTickPrescaler >= IGMP_TICK_INTERVAL)
      {
         //Loop through network interfaces
         for(i = 0; i < NET_INTERFACE_COUNT; i++)
         {
            //Make sure the interface has been properly configured
            if(netInterface[i].configured)
               igmpTick(&netInterface[i]);
         }

         //Clear prescaler
         igmpTickPrescaler = 0;
      }
#endif

#if (IPV6_SUPPORT == ENABLED)
      //Update prescaler
      ndpTickPrescaler += TCP_IP_TICK_INTERVAL;

      //Manage Neighbor cache
      if(ndpTickPrescaler >= NDP_TICK_INTERVAL)
      {
         //Loop through network interfaces
         for(i = 0; i < NET_INTERFACE_COUNT; i++)
         {
            //Make sure the interface has been properly configured
            if(netInterface[i].configured)
               ndpTick(&netInterface[i]);
         }

         //Clear prescaler
         ndpTickPrescaler = 0;
      }
#endif

#if (IPV6_SUPPORT == ENABLED && IPV6_FRAG_SUPPORT == ENABLED)
      //Update prescaler
      ipv6FragTickPrescaler += TCP_IP_TICK_INTERVAL;

      //Handle IPv4 fragment reassembly timeout
      if(ipv6FragTickPrescaler >= IPV6_FRAG_TICK_INTERVAL)
      {
         //Loop through network interfaces
         for(i = 0; i < NET_INTERFACE_COUNT; i++)
         {
            //Make sure the interface has been properly configured
            if(netInterface[i].configured)
               ipv6FragTick(&netInterface[i]);
         }

         //Clear prescaler
         ipv6FragTickPrescaler = 0;
      }
#endif

#if (IPV6_SUPPORT == ENABLED && MLD_SUPPORT == ENABLED)
      //Update prescaler
      mldTickPrescaler += TCP_IP_TICK_INTERVAL;

      //Handle MLD related timers
      if(mldTickPrescaler >= MLD_TICK_INTERVAL)
      {
         //Loop through network interfaces
         for(i = 0; i < NET_INTERFACE_COUNT; i++)
         {
            //Make sure the interface has been properly configured
            if(netInterface[i].configured)
               mldTick(&netInterface[i]);
         }

         //Clear prescaler
         mldTickPrescaler = 0;
      }
#endif

#if (TCP_SUPPORT == ENABLED)
      //Update TCP tick prescaler
      tcpTickPrescaler += TCP_IP_TICK_INTERVAL;

      //Manage TCP related timers
      if(tcpTickPrescaler >= TCP_TICK_INTERVAL)
      {
         //TCP timer handler
         tcpTick();
         //Clear prescaler
         tcpTickPrescaler = 0;
      }
#endif
   }
}


/**
 * @brief Task in charge of processing incoming frames
 * @param[in] param Underlying network interface
 **/

void tcpIpStackRxTask(void *param)
{
   //Point to the structure describing the network interface
   NetInterface *interface = (NetInterface *) param;

   //Main loop
   while(1)
   {
      //Receive notifications when a Ethernet frame has been received,
      //or the link status has changed
      osEventWait(interface->nicRxEvent, INFINITE_DELAY);

      //Get exclusive access to the device
      osMutexAcquire(interface->nicDriverMutex);
      //Disable Ethernet controller interrupts
      interface->nicDriver->disableIrq(interface);

      //Handle incoming packets and link state changes
      interface->nicDriver->rxEventHandler(interface);

      //Re-enable Ethernet controller interrupts
      interface->nicDriver->enableIrq(interface);
      //Release exclusive access to the device
      osMutexRelease(interface->nicDriverMutex);
   }
}


/**
 * @brief Get default network interface
 * @return Pointer to the default network interface to be used
 **/

NetInterface *tcpIpStackGetDefaultInterface(void)
{
   //Default network interface
   return &netInterface[0];
}

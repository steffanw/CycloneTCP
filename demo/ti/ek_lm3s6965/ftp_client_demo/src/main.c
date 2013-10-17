/**
 * @file main.c
 * @brief Main routine
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

//Dependencies
#include <stdio.h>
#include "lm3s6965.h"
#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "driverlib/gpio.h"
#include "driverlib/sysctl.h"
#include "rit128x96x4.h"
#include "os.h"
#include "tcp_ip_stack.h"
#include "lm3s_eth.h"
#include "dhcp_client.h"
#include "dhcpv6_client.h"
#include "ftp_client.h"
#include "debug.h"

//Global variables
uint_t lcdLine = 0;
uint_t lcdColumn = 0;


/**
 * @brief Set cursor location
 * @param[in] line Line number
 * @param[in] column Column number
 **/

void lcdSetCursor(uint_t line, uint_t column)
{
   lcdLine = min(line, 10);
   lcdColumn = min(column, 20);
}


/**
 * @brief Write a character to the LCD display
 * @param[in] c Character to be written
 **/

void lcdPutChar(char_t c)
{
   if(c == '\r')
   {
      lcdColumn = 0;
   }
   else if(c == '\n')
   {
      lcdColumn = 0;
      lcdLine++;
   }
   else if(lcdLine < 8 && lcdColumn < 21)
   {
      char_t buffer[2];
      buffer[0] = c;
      buffer[1] = '\0';

      //Display current character
      RIT128x96x4StringDraw(buffer, lcdColumn * 6, lcdLine * 12, 15);

      //Advance the cursor position
      if(++lcdColumn >= 21)
      {
         lcdColumn = 0;
         lcdLine++;
      }
   }
}


/**
 * @brief FTP client test routine
 * @return Error code
 **/

error_t ftpClientTest(void)
{
   error_t error;
   size_t length;
   IpAddr ipAddr;
   FtpClientContext ftpContext;
   static char_t buffer[256];

   //Debug message
   TRACE_INFO("\r\n\r\nResolving server name...\r\n");
   //Resolve FTP server name
   error = getHostByName(NULL, "ftp.gnu.org", &ipAddr, 1, NULL, 0);

   //Any error to report?
   if(error)
   {
      //Debug message
      TRACE_INFO("Failed to resolve server name!\r\n");
      //Exit immedialtely
      return error;
   }

   //Debug message
   TRACE_INFO("Connecting to FTP server %s\r\n", ipAddrToString(&ipAddr, NULL));
   //Connect to the FTP server
   error = ftpConnect(&ftpContext, NULL, &ipAddr, 21, FTP_NO_SECURITY | FTP_PASSIVE_MODE);

   //Any error to report?
   if(error)
   {
      //Debug message
      TRACE_INFO("Failed to connect to FTP server!\r\n");
      //Exit immedialtely
      return error;
   }

   //Debug message
   TRACE_INFO("Successful connection\r\n");

   //Start of exception handling block
   do
   {
      //Login to the FTP server using the provided username and password
      error = ftpLogin(&ftpContext, "anonymous", "password", "");
      //Any error to report?
      if(error) break;

      //Open the specified file for reading
      error = ftpOpenFile(&ftpContext, "welcome.msg", FTP_FOR_READING | FTP_BINARY_TYPE);
      //Any error to report?
      if(error) break;

      //Dump the contents of the file
      while(1)
      {
         //Read data
         error = ftpReadFile(&ftpContext, buffer, sizeof(buffer) - 1, &length, 0);
         //End of file?
         if(error) break;

         //Properly terminate the string with a NULL character
         buffer[length] = '\0';
         //Dump current data
         TRACE_INFO("%s", buffer);
      }

      //End the string with a line feed
      TRACE_INFO("\r\n");
      //Close the file
      error = ftpCloseFile(&ftpContext);

      //End of exception handling block
   } while(0);

   //Close the connection
   ftpClose(&ftpContext);
   //Debug message
   TRACE_INFO("Connection closed...\r\n");

   //Return status code
   return error;
}


/**
 * @brief User task
 **/

void userTask(void *param)
{
   char_t buffer[40];

   //Point to the network interface
   NetInterface *interface = &netInterface[0];

   //Display IPv4 address
   lcdSetCursor(2, 0);
   printf("IPv4 Addr");
   lcdSetCursor(5, 0);
   printf("Press SELECT button\r\nto run test");

   //Endless loop
   while(1)
   {
      //Refresh IPv4 address
      lcdSetCursor(3, 0);
      printf("%-16s", ipv4AddrToString(interface->ipv4Config.addr, buffer));

      //SELECT button pressed?
      if(!GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_1))
      {
         //FTP client test routine
         ftpClientTest();

         //Wait for the SELECT button to be released
         while(!GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_1));
      }

      //100ms delay
      osDelay(100);
   }
}


/**
 * @brief LED blinking task
 **/

void blinkTask(void *parameters)
{
   while(1)
   {
      GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_0, GPIO_PIN_0);
      osDelay(100);
      GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_0, 0);
      osDelay(900);
   }
}


/**
 * @brief Main entry point
 * @return Unused value
 **/

int_t main(void)
{
   error_t error;
   Ipv6Addr solicitedNodeAddr;
   NetInterface *interface;
   OsTask *task;

   static DhcpClientSettings dhcpClientSettings;
   static DhcpClientCtx dhcpClientContext;
   static Dhcpv6ClientSettings dhcpv6ClientSettings;
   static Dhcpv6ClientCtx dhcpv6ClientContext;

   //Configure debug UART
   debugInit(115200);

   //Start-up message
   TRACE_INFO("\r\n");
   TRACE_INFO("**********************************\r\n");
   TRACE_INFO("*** CycloneTCP FTP Client Demo ***\r\n");
   TRACE_INFO("**********************************\r\n");
   TRACE_INFO("Copyright: 2010-2013 Oryx Embedded\r\n");
   TRACE_INFO("Compiled: %s %s\r\n", __DATE__, __TIME__);
   TRACE_INFO("Target: LM3S6965\r\n");
   TRACE_INFO("\r\n");

   //Enable GPIO clocks
   SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOE);
   SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

   //Configure LED
   GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_0);

   //Configure UP, DOWN, LEFT and RIGHT buttons
   GPIOPinTypeGPIOInput(GPIO_PORTE_BASE, GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3);
   //Enable weak pull-ups
   GPIOPadConfigSet(GPIO_PORTE_BASE, GPIO_PIN_0 | GPIO_PIN_1 | GPIO_PIN_2 | GPIO_PIN_3,
      GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD_WPU);

   //Configure SELECT button
   GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_1);
   //Enable weak pull-up
   GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_1,
      GPIO_STRENGTH_2MA, GPIO_PIN_TYPE_STD_WPU);

   //Initialize LCD display
   RIT128x96x4Init(1000000);

   //Welcome message
   lcdSetCursor(0, 0);
   printf("FTP Client Demo");

   //TCP/IP stack initialization
   error = tcpIpStackInit();

   //Any error to report?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to initialize TCP/IP stack!\r\n");
   }

   //Configure the first Ethernet interface
   interface = &netInterface[0];
   //Select the relevant network adapter
   interface->nicDriver = &lm3sEthDriver;
   //Interface name
   strcpy(interface->name, "eth0");
   //Set host MAC address
   macStringToAddr("00-AB-CD-EF-69-65", &interface->macAddr);

#if (IPV6_SUPPORT == ENABLED)
   //Set link-local IPv6 address
   ipv6StringToAddr("fe80::00ab:cdef:6965", &interface->ipv6Config.linkLocalAddr);
#endif

   //Initialize network interface
   error = tcpIpStackConfigInterface(interface);

   //Any error to report?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to configure interface %s!\r\n", interface->name);
   }

#if 1
   //Set the network interface to be configured by DHCP
   dhcpClientSettings.interface = &netInterface[0];
   //Disable rapid commit option
   dhcpClientSettings.rapidCommit = FALSE;
   //Start DHCP client
   error = dhcpClientStart(&dhcpClientContext, &dhcpClientSettings);

   //Failed to start DHCP client?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to start DHCP client!\r\n");
   }
#else
   //Manual configuration
   interface = &netInterface[0];

   //IPv4 address
   ipv4StringToAddr("192.168.0.20", &interface->ipv4Config.addr);
   //Subnet mask
   ipv4StringToAddr("255.255.255.0", &interface->ipv4Config.subnetMask);
   //Default gateway
   ipv4StringToAddr("192.168.0.254", &interface->ipv4Config.defaultGateway);

   //Primary and secondary DNS servers
   interface->ipv4Config.dnsServerCount = 2;
   ipv4StringToAddr("212.27.40.240", &interface->ipv4Config.dnsServer[0]);
   ipv4StringToAddr ("212.27.40.241", &interface->ipv4Config.dnsServer[1]);
#endif

#if (IPV6_SUPPORT == ENABLED)
#if 0
   //Set the network interface to be configured by DHCPv6
   dhcpv6ClientSettings.interface = &netInterface[0];
   //Disable rapid commit option
   dhcpv6ClientSettings.rapidCommit = FALSE;
   //Start DHCPv6 client
   error = dhcpv6ClientStart(&dhcpv6ClientContext, &dhcpv6ClientSettings);

   //Failed to start DHCPv6 client?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to start DHCPv6 client!\r\n");
   }
#else
   //Manual configuration
   interface = &netInterface[0];

   //Prefix
   interface->ipv6Config.prefixLength = 64;
   ipv6StringToAddr("2a01:e35:8a47:b350::", &interface->ipv6Config.prefix);

   //Global address
   ipv6StringToAddr("2a01:e35:8a47:b350::6965", &interface->ipv6Config.globalAddr);
   //Router
   ipv6StringToAddr("fe80::207:cbff:fe91:ebfd", &interface->ipv6Config.router);

   //Primary and secondary DNS servers
   interface->ipv6Config.dnsServerCount = 2;
   ipv6StringToAddr("2a01:e00::1", &interface->ipv6Config.dnsServer[0]);
   ipv6StringToAddr("2a01:e00::2", &interface->ipv6Config.dnsServer[1]);

   //A host is required to join a Solicited-Node multicast group for each of
   //its configured unicast address
   ipv6ComputeSolicitedNodeAddr(&interface->ipv6Config.globalAddr, &solicitedNodeAddr);
   ipv6JoinMulticastGroup(interface, &solicitedNodeAddr);
#endif
#endif

   //Create user task
   task = osTaskCreate("User Task", userTask, NULL, 500, 1);
   //Failed to create the task?
   if(task == OS_INVALID_HANDLE)
   {
      //Debug message
      TRACE_ERROR("Failed to create task!\r\n");
   }

   //Create a task to blink the LED
   task = osTaskCreate("Blink", blinkTask, NULL, 500, 1);
   //Failed to create the task?
   if(task == OS_INVALID_HANDLE)
   {
      //Debug message
      TRACE_ERROR("Failed to create task!\r\n");
   }

   //Start the execution of tasks
   osStart();

   //This function should never return
   return 0;
}

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
#include "lpc1766_stk.h"
#include "lcd.h"
#include "os.h"
#include "tcp_ip_stack.h"
#include "lpc176x_eth.h"
#include "ksz8721.h"
#include "dhcp_client.h"
#include "ftp_client.h"
#include "error.h"
#include "debug.h"


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
   printf("IPv4 Addr:");
   lcdSetCursor(5, 0);
   printf("Press BUT1 to\r\nrun test");

   //Endless loop
   while(1)
   {
      //Refresh IPv4 address
      lcdSetCursor(3, 0);
      printf("%-16s", ipv4AddrToString(interface->ipv4Config.addr, buffer));

      //BUT1 button pressed?
      if(!(BUTTON1_FIOPIN & BUTTON1_MASK))
      {
         //FTP client test routine
         ftpClientTest();

         //Wait for the button to be released
         while(!(BUTTON1_FIOPIN & BUTTON1_MASK));
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
      LED1_FIOCLR = LED1_MASK;
      osDelay(100);
      LED1_FIOSET = LED1_MASK;
      osDelay(900);
   }
}


/**
 * @brief I/O initialization
 **/

void ioInit(void)
{
   //Configure LED1
   LED1_FIOSET = LED1_MASK;
   LED1_FIODIR |= LED1_MASK;

   //Configure LED2
   LED2_FIOSET = LED2_MASK;
   LED2_FIODIR |= LED2_MASK;

   //Configure USB link LED
   LED_USB_LINK_FIOSET = LED_USB_LINK_MASK;
   LED_USB_LINK_FIODIR |= LED_USB_LINK_MASK;

   //Configure USB connect LED
   LED_USB_CONNECT_FIOSET = LED_USB_CONNECT_MASK;
   LED_USB_CONNECT_FIODIR |= LED_USB_CONNECT_MASK;

   //Configure buttons
   BUTTON1_FIODIR &= ~BUTTON1_MASK;
   BUTTON2_FIODIR &= ~BUTTON2_MASK;
   BUTTON_WUP_FIODIR &= ~BUTTON_WUP_MASK;

   //Configure joystick
   JOYSTISK_FIODIR &= ~(JOYSTISK_UP_MASK | JOYSTISK_DOWN_MASK | JOYSTISK_LEFT_MASK | JOYSTISK_RIGHT_MASK);
   JOYSTISK_CENTER_FDIR &= ~JOYSTISK_CENTER_MASK;
}


/**
 * @brief Main entry point
 * @return Unused value
 **/

int_t main(void)
{
   error_t error;
   NetInterface *interface;
   OsTask *task;

   static DhcpClientSettings dhcpClientSettings;
   static DhcpClientCtx dhcpClientContext;

   //Configure debug UART
   debugInit(115200);

   //Start-up message
   TRACE_INFO("\r\n");
   TRACE_INFO("**********************************\r\n");
   TRACE_INFO("*** CycloneTCP FTP Client Demo ***\r\n");
   TRACE_INFO("**********************************\r\n");
   TRACE_INFO("Copyright: 2010-2013 Oryx Embedded\r\n");
   TRACE_INFO("Compiled: %s %s\r\n", __DATE__, __TIME__);
   TRACE_INFO("Target: LPC1766\r\n");
   TRACE_INFO("\r\n");

   //Configure I/Os
   ioInit();

   //Initialize LCD display
   lcdInit();
   //Turn on backlight
   lcdSetBacklight(TRUE);
   //Set foreground and background colors
   lcdSetForegroundColor(WHITE);
   lcdSetBackgroundColor(BLUE);
   //Clear display
   lcdClear();

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
   interface->nicDriver = &lpc176xEthDriver;
   interface->phyDriver = &ksz8721PhyDriver;
   //Interface name
   strcpy(interface->name, "eth0");
   //Set host MAC address
   macStringToAddr("00-AB-CD-EF-17-66", &interface->macAddr);

#if (IPV6_SUPPORT == ENABLED)
   //Set link-local IPv6 address
   ipv6StringToAddr("fe80::00ab:cdef:1766", &interface->ipv6Config.linkLocalAddr);
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

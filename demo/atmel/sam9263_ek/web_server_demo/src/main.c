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
#include <stdlib.h>
#include "sam9263_ek.h"
#include "os.h"
#include "tcp_ip_stack.h"
#include "sam9263_eth.h"
#include "dm9161.h"
#include "dhcp_client.h"
#include "dhcpv6_client.h"
#include "echo.h"
#include "discard.h"
#include "chargen.h"
#include "smtp_client.h"
#include "http_server.h"
#include "mime.h"
#include "yarrow.h"
#include "ping.h"
#include "str.h"
#include "resource_manager.h"
#include "debug.h"

//Forward declaration of functions
error_t httpServerCgiCallback(HttpConnection *connection, const char_t *param);
error_t httpServerUriNotFoundCallback(HttpConnection *connection);

//Global variables
YarrowContext yarrowContext;
uint8_t seed[32];

uint_t lcdLine = 0;
uint_t lcdColumn = 0;
uint_t adcValue = 0;
uint_t joystickState = 0;
int8_t ax = 0;
int8_t ay = 0;
int8_t az = 0;


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
   else if(lcdLine < 10 && lcdColumn < 20)
   {
      //Display current character
      //LCD_DisplayChar(lcdLine * 24, 319 - (lcdColumn * 16), c);

      //Advance the cursor position
      if(++lcdColumn >= 20)
      {
         lcdColumn = 0;
         lcdLine++;
      }
   }
}


/**
 * @brief LED blinking task
 **/

void blinkTask(void *parameters)
{
   while(1)
   {
      //Blink LED1 and LED2
      AT91D_BASE_PIO_LED1->PIO_CODR = AT91B_LED1;
      AT91D_BASE_PIO_LED2->PIO_SODR = AT91B_LED2;
      osDelay(500);

      AT91D_BASE_PIO_LED1->PIO_SODR = AT91B_LED1;
      AT91D_BASE_PIO_LED2->PIO_CODR = AT91B_LED2;
      osDelay(500);
   }
}


/**
 * @brief I/O initialization
 **/

void ioInit(void)
{
   //Enable the peripheral clock of PIO controllers
   AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_PIOA) | (1 << AT91C_ID_PIOB) | (1 << AT91C_ID_PIOCDE);

   //Configure LED1
   AT91D_BASE_PIO_LED1->PIO_PER = AT91B_LED1;
   AT91D_BASE_PIO_LED1->PIO_OER = AT91B_LED1;
   AT91D_BASE_PIO_LED1->PIO_SODR = AT91B_LED1;

   //Configure LED2
   AT91D_BASE_PIO_LED2->PIO_PER = AT91B_LED2;
   AT91D_BASE_PIO_LED2->PIO_OER = AT91B_LED2;
   AT91D_BASE_PIO_LED2->PIO_SODR = AT91B_LED2;

   //Configure LED3
   AT91D_BASE_PIO_LED3->PIO_PER = AT91B_LED3;
   AT91D_BASE_PIO_LED3->PIO_OER = AT91B_LED3;
   AT91D_BASE_PIO_LED3->PIO_CODR = AT91B_LED3;
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
   static HttpServerSettings httpServerSettings;
   static HttpServerContext httpServerContext;

   //Configure debug UART
   debugInit(115200);

   //Start-up message
   TRACE_INFO("\r\n");
   TRACE_INFO("**********************************\r\n");
   TRACE_INFO("*** CycloneTCP Web Server Demo ***\r\n");
   TRACE_INFO("**********************************\r\n");
   TRACE_INFO("Copyright: 2010-2013 Oryx Embedded\r\n");
   TRACE_INFO("Compiled: %s %s\r\n", __DATE__, __TIME__);
   TRACE_INFO("Target: SAM9263\r\n");
   TRACE_INFO("\r\n");

   //IO configuration
   ioInit();

   //PRNG initialization
   error = yarrowInit(&yarrowContext);

   //Any error to report?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to initialize PRNG!\r\n");
   }

   //Generate a random seed

   //Properly seed the PRNG
   error = yarrowSeed(&yarrowContext, seed, sizeof(seed));

   //Any error to report?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to seed PRNG!\r\n");
   }

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
   interface->nicDriver = &sam9263EthDriver;
   interface->phyDriver = &dm9161PhyDriver;
   //Interface name
   strcpy(interface->name, "eth0");
   //Set host MAC address
   macStringToAddr("00-AB-CD-EF-92-63", &interface->macAddr);

#if (IPV6_SUPPORT == ENABLED)
   //Set link-local IPv6 address
   ipv6StringToAddr("fe80::00ab:cdef:9263", &interface->ipv6Config.linkLocalAddr);
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
   ipv6StringToAddr("2a01:e35:8a47:b350::0207", &interface->ipv6Config.globalAddr);
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

   //Bind HTTP server to the desired interface
   httpServerSettings.interface = &netInterface[0];
   //Listen to port 80
   httpServerSettings.port = HTTP_PORT;
   //Specify the server's root directory
   strcpy(httpServerSettings.rootDirectory, "/www/");
   //Set default home page
   strcpy(httpServerSettings.defaultDocument, "index.shtm");
   //Callback functions
   httpServerSettings.cgiCallback = httpServerCgiCallback;
   httpServerSettings.uriNotFoundCallback = httpServerUriNotFoundCallback;
   //Start HTTP server
   error = httpServerStart(&httpServerContext, &httpServerSettings);

   //Failed to start HTTP server?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to start HTTP server!\r\n");
   }

   //Start TCP echo service
   error = tcpEchoStart();
   //Failed to TCP echo service?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to start TCP echo service!\r\n");
   }

   //Start UDP echo service
   error = udpEchoStart();
   //Failed to TCP echo service?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to start UDP echo service!\r\n");
   }

   //Start TCP discard service
   error = tcpDiscardStart();
   //Failed to TCP echo service?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to start TCP discard service!\r\n");
   }

   //Start UDP discard service
   error = udpDiscardStart();
   //Failed to TCP echo service?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to start UDP discard service!\r\n");
   }

   //Start TCP chargen service
   error = tcpChargenStart();
   //Failed to TCP echo service?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to start TCP chargen service!\r\n");
   }

   //Start UDP chargen service
   error = udpChargenStart();
   //Failed to TCP echo service?
   if(error)
   {
      //Debug message
      TRACE_ERROR("Failed to start UDP chargen service!\r\n");
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


/**
 * @brief CGI callback function
 **/

error_t httpServerCgiCallback(HttpConnection *connection, const char_t *param)
{
   static uint_t pageCounter = 0;
   uint_t length;

   //Underlying network interface
   NetInterface *interface = connection->socket->interface;

   //Check parameter name
   if(!strcasecmp(param, "PAGE_COUNTER"))
   {
      pageCounter++;
      sprintf(connection->buffer, "%u time%s", pageCounter, (pageCounter >= 2) ? "s" : "");
   }
   else if(!strcasecmp(param, "BOARD_NAME"))
   {
      strcpy(connection->buffer, "SAM9263-EK");
   }
   else if(!strcasecmp(param, "SYSTEM_TIME"))
   {
      time_t time = osGetTickCount();
      sprintf(connection->buffer, "%us %03ums", time / 1000, time % 1000);
   }
   else if(!strcasecmp(param, "MAC_ADDR"))
   {
      macAddrToString(&interface->macAddr, connection->buffer);
   }
   else if(!strcasecmp(param, "IPV4_ADDR"))
   {
      ipv4AddrToString(interface->ipv4Config.addr, connection->buffer);
   }
   else if(!strcasecmp(param, "SUBNET_MASK"))
   {
      ipv4AddrToString(interface->ipv4Config.subnetMask, connection->buffer);
   }
   else if(!strcasecmp(param, "DEFAULT_GATEWAY"))
   {
      ipv4AddrToString(interface->ipv4Config.defaultGateway, connection->buffer);
   }
   else if(!strcasecmp(param, "IPV4_PRIMARY_DNS"))
   {
      ipv4AddrToString(interface->ipv4Config.dnsServer[0], connection->buffer);
   }
   else if(!strcasecmp(param, "IPV4_SECONDARY_DNS"))
   {
      ipv4AddrToString(interface->ipv4Config.dnsServer[1], connection->buffer);
   }
#if (IPV6_SUPPORT == ENABLED)
   else if(!strcasecmp(param, "LINK_LOCAL_ADDR"))
   {
      ipv6AddrToString(&interface->ipv6Config.linkLocalAddr, connection->buffer);
   }
   else if(!strcasecmp(param, "GLOBAL_ADDR"))
   {
      ipv6AddrToString(&interface->ipv6Config.globalAddr, connection->buffer);
   }
   else if(!strcasecmp(param, "IPV6_PREFIX"))
   {
      ipv6AddrToString(&interface->ipv6Config.prefix, connection->buffer);
      length = strlen(connection->buffer);
      sprintf(connection->buffer + length, "/%u", interface->ipv6Config.prefixLength);
   }
   else if(!strcasecmp(param, "ROUTER"))
   {
      ipv6AddrToString(&interface->ipv6Config.router, connection->buffer);
   }
   else if(!strcasecmp(param, "IPV6_PRIMARY_DNS"))
   {
      ipv6AddrToString(&interface->ipv6Config.dnsServer[0], connection->buffer);
   }
   else if(!strcasecmp(param, "IPV6_SECONDARY_DNS"))
   {
      ipv6AddrToString(&interface->ipv6Config.dnsServer[1], connection->buffer);
   }
#endif
   else
   {
      return ERROR_INVALID_TAG;
   }

   //Get the length of the resulting string
   length = strlen(connection->buffer);

   //Send the contents of the specified environment variable
   return httpWriteStream(connection, connection->buffer, length);
}


/**
 * @brief URI not found callback
 **/

error_t httpServerUriNotFoundCallback(HttpConnection *connection)
{
   error_t error;
   uint_t i;
   uint_t j;
   uint_t n;
   char_t *buffer;

   //Process data.xml file?
   if(!strcasecmp(connection->request.uri, "/data.xml"))
   {
      //Point to the scratch buffer
      buffer = connection->buffer + 384;

      //Format XML data
      n = sprintf(buffer, "<data>\r\n");
      n += sprintf(buffer + n, "  <ax>%d</ax>\r\n", ax);
      n += sprintf(buffer + n, "  <ay>%d</ay>\r\n", ay);
      n += sprintf(buffer + n, "  <az>%d</az>\r\n", az);
      n += sprintf(buffer + n, "  <adc>%u</adc>\r\n", adcValue);
      n += sprintf(buffer + n, "  <joystick>%u</joystick>\r\n", joystickState);

      //End of XML data
      n += sprintf(buffer + n, "</data>\r\n");

      //Format HTTP response header
      connection->response.version = connection->request.version;
      connection->response.statusCode = 200;
      connection->response.keepAlive = connection->request.keepAlive;
      connection->response.noCache = TRUE;
      connection->response.contentType = mimeGetType(".xml");
      connection->response.chunkedEncoding = FALSE;
      connection->response.contentLength = n;

      //Send the header to the client
      error = httpWriteHeader(connection);
      //Any error to report?
      if(error) return error;

      //Send response body
      error = httpWriteStream(connection, buffer, n);
      //Any error to report?
      if(error) return error;

      //Properly close output stream
      error = httpCloseStream(connection);
      //Return status code
      return error;
   }
   //Process send_mail.xml file?
   else if(!strcasecmp(connection->request.uri, "/send_mail.xml"))
   {
      char *separator;
      char *property;
      char *value;
      char *p;
      SmtpAuthInfo authInfo;
      SmtpMail mail;
      SmtpMailAddr recipients[4];

      //Initialize structures to zero
      memset(&authInfo, 0, sizeof(authInfo));
      memset(&mail, 0, sizeof(mail));
      memset(recipients, 0, sizeof(recipients));

      //Set the relevant PRNG algorithm to be used
      authInfo.prngAlgo = YARROW_PRNG_ALGO;
      authInfo.prngContext = &yarrowContext;

      //Set email recipients
      mail.recipients = recipients;
      //Point to the scratch buffer
      buffer = connection->buffer;

      //Start of exception handling block
      do
      {
         //Process HTTP request body
         while(1)
         {
            //Read the HTTP request body until a ampersand is encountered
            error = httpReadStream(connection, buffer,
               HTTP_SERVER_BUFFER_SIZE - 1, &n, HTTP_FLAG_BREAK('&'));
            //End of stream detected?
            if(error) break;

            //Properly terminate the string with a NULL character
            buffer[n] = '\0';

            //Remove the trailing ampersand
            if(n > 0 && buffer[n - 1] == '&')
               buffer[--n] = '\0';

            //Decode the percent-encoded string
            for(i = 0, j = 0; i < n; i++, j++)
            {
               //Replace '+' characters with spaces
               if(buffer[i] == '+')
               {
                  buffer[j] = ' ';
               }
               //Process percent-encoded characters
               else if(buffer[i] == '%' && (i + 2) < n)
               {
                  buffer[i] = buffer[i + 1];
                  buffer[i + 1] = buffer[i + 2];
                  buffer[i + 2] = '\0';
                  buffer[j] = strtoul(buffer + i, NULL, 16);
                  i += 2;
               }
               //Copy any other characters
               else
               {
                  buffer[j] = buffer[i];
               }
            }

            //Properly terminate the resulting string
            buffer[j] = '\0';

            //Check whether a separator is present
            separator = strchr(buffer, '=');

            //Separator found?
            if(separator)
            {
               //Split the line
               *separator = '\0';
               //Get property name and value
               property = strTrimWhitespace(buffer);
               value = strTrimWhitespace(separator + 1);

               //Check property name
               if(!strcasecmp(property, "server"))
               {
                  //Save server name
                  authInfo.serverName = strDuplicate(value);
               }
               else if(!strcasecmp(property, "port"))
               {
                  //Save the server port to be used
                  authInfo.serverPort = atoi(value);
               }
               else if(!strcasecmp(property, "userName"))
               {
                  //Save user name
                  authInfo.userName = strDuplicate(value);
               }
               else if(!strcasecmp(property, "password"))
               {
                  //Save password
                  authInfo.password = strDuplicate(value);
               }
               else if(!strcasecmp(property, "useTls"))
               {
                  //Open a secure SSL/TLS session?
                  authInfo.useTls = TRUE;
               }
               else if(!strcasecmp(property, "recipient"))
               {
                  //Split the recipient address list
                  value = strtok_r(value, ", ", &p);

                  //Loop through the list
                  while(value != NULL)
                  {
                     //Save recipient address
                     recipients[mail.recipientCount].name = NULL;
                     recipients[mail.recipientCount].addr = strDuplicate(value);
                     recipients[mail.recipientCount].type = SMTP_RCPT_TYPE_TO;
                     //Get the next item in the list
                     value = strtok_r(NULL, ", ", &p);

                     //Increment the number of recipients
                     if(++mail.recipientCount >= arraysize(recipients))
                        break;
                  }
               }
               else if(!strcasecmp(property, "from"))
               {
                  //Save sender address
                  mail.from.name = NULL;
                  mail.from.addr = strDuplicate(value);
               }
               else if(!strcasecmp(property, "date"))
               {
                  //Save current time
                  mail.dateTime = strDuplicate(value);
               }
               else if(!strcasecmp(property, "subject"))
               {
                  //Save mail subject
                  mail.subject = strDuplicate(value);
               }
               else if(!strcasecmp(property, "body"))
               {
                  //Save mail body
                  mail.body = strDuplicate(value);
               }
            }
         }

         //Propagate exception if necessary
         if(error != ERROR_END_OF_STREAM)
            break;

         //Send mail
         error = smtpSendMail(&authInfo, &mail);

         //Point to the scratch buffer
         buffer = connection->buffer + 384;
         //Format XML data
         n = sprintf(buffer, "<data>\r\n  <status>");

         if(error == NO_ERROR)
            n += sprintf(buffer + n, "Mail successfully sent!\r\n");
         else if(error == ERROR_NAME_RESOLUTION_FAILED)
            n += sprintf(buffer + n, "Cannot resolve SMTP server name!\r\n");
         else if(error == ERROR_AUTHENTICATION_FAILED)
            n += sprintf(buffer + n, "Authentication failed!\r\n");
         else if(error == ERROR_UNEXPECTED_RESPONSE)
            n += sprintf(buffer + n, "Unexpected response from SMTP server!\r\n");
         else
            n += sprintf(buffer + n, "Failed to send mail (error %d)!\r\n", error);

         n += sprintf(buffer + n, "</status>\r\n</data>\r\n");

         //Format HTTP response header
         connection->response.version = connection->request.version;
         connection->response.statusCode = 200;
         connection->response.keepAlive = connection->request.keepAlive;
         connection->response.noCache = TRUE;
         connection->response.contentType = mimeGetType(".xml");
         connection->response.chunkedEncoding = FALSE;
         connection->response.contentLength = n;

         //Send the header to the client
         error = httpWriteHeader(connection);
         //Any error to report?
         if(error) break;

         //Send response body
         error = httpWriteStream(connection, buffer, n);
         //Any error to report?
         if(error) break;

         //Properly close output stream
         error = httpCloseStream(connection);
         //Any error to report?
         if(error) break;

         //End of exception handling block
      } while(0);

      //Free previously allocated memory
      osMemFree((void *) authInfo.serverName);
      osMemFree((void *) authInfo.userName);
      osMemFree((void *) authInfo.password);
      osMemFree((void *) recipients[0].addr);
      osMemFree((void *) mail.from.addr);
      osMemFree((void *) mail.dateTime);
      osMemFree((void *) mail.subject);
      osMemFree((void *) mail.body);

      //Return status code
      return error;
   }
   else
   {
      return ERROR_NOT_FOUND;
   }
}

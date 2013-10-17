/**
 * @file ssi.c
 * @brief SSI (Server Side Includes)
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
 * @section Description
 *
 * Server Side Includes (SSI) is a simple interpreted server-side scripting
 * language used to generate dynamic content to web pages
 *
 * @author Oryx Embedded (www.oryx-embedded.com)
 * @version 1.3.8
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL HTTP_TRACE_LEVEL

//Dependencies
#include "tcp_ip_stack.h"
#include "http_server.h"
#include "mime.h"
#include "ssi.h"
#include "resource_manager.h"
#include "str.h"
#include "debug.h"


/**
 * @brief Execute SSI script
 * @param[in] connection Structure representing an HTTP connection
 * @param[in] uri NULL terminated string containing the file to process
 * @param[in] level Current level of recursion
 * @return Error code
 **/

error_t ssiExecuteScript(HttpConnection *connection, const char_t *uri, uint_t level)
{
   error_t error;
   int_t i;
   int_t j;
   size_t length;
   char_t *data;

   //Recursion exceeded?
   if(level >= HTTP_SERVER_SSI_MAX_RECURSION)
      return NO_ERROR;

   //Get absolute path to the specified URI
   httpGetAbsolutePath(connection, uri, connection->buffer);

   //Get the resource data associated with the URI
   error = resGetData(connection->buffer, (uint8_t **) &data, &length);
   //The specified URI cannot be found?
   if(error) return error;

   //Send the HTTP response header before executing the script
   if(!level)
   {
      //Format HTTP response header
      connection->response.version = connection->request.version;
      connection->response.statusCode = 200;
      connection->response.keepAlive = connection->request.keepAlive;
      connection->response.noCache = FALSE;
      connection->response.contentType = mimeGetType(connection->request.uri);
      connection->response.chunkedEncoding = TRUE;

      //Send the header to the client
      error = httpWriteHeader(connection);
      //Any error to report?
      if(error) return error;
   }

   //Parse the specified file
   while(length > 0)
   {
      //Search for any SSI tags
      i = ssiSearchTag(data, length, "<!--#", 5);

      //Opening identifier found?
      if(i >= 0)
      {
         //Search for the comment terminator
         j = ssiSearchTag(data + i + 5, length - i - 5, "-->", 3);
      }
      else
      {
         j = -1;
      }

      //Check whether a valid SSI tag has been found?
      if(i > 0 && j > 0)
      {
         //Send the part of the file that precedes the tag
         error = httpWriteStream(connection, data, i);
         //Failed to send data?
         if(error) return error;

         //Advance data pointer over the opening identifier
         data += i + 5;
         length -= i + 5;

         //Include command found?
         if(j > 7 && !strncasecmp(data, "include", 7))
         {
            //Process SSI include directive
            error = ssiProcessIncludeCommand(connection, data, j, uri, level);
         }
         //Echo command found?
         else if(j > 4 && !strncasecmp(data, "echo", 4))
         {
            //Process SSI echo directive
            error = ssiProcessEchoCommand(connection, data, j);
         }
         //Exec command found?
         else if(j > 4 && !strncasecmp(data, "exec", 4))
         {
            //Process SSI exec directive
            error = ssiProcessExecCommand(connection, data, j);
         }
         //Unknown command?
         else
         {
            //The server is unable to decode the SSI tag
            error = ERROR_INVALID_TAG;
         }

         //Check whether the tag was successfully decoded or not
         if(error == ERROR_INVALID_TAG)
         {
            //Report a warning to the user
            error = httpWriteStream(connection, "Warning: Invalid SSI Tag", 24);
            //Failed to send data?
            if(error) return error;
         }
         //Any other error to report?
         else if(error)
         {
            //Exit immediately
            return error;
         }

         //Advance data pointer over the SSI tag
         data += j + 3;
         length -= j + 3;
      }
      else
      {
         //Send the rest of the file
         error = httpWriteStream(connection, data, length);
         //Failed to send data?
         if(error) return error;
         //Advance data pointer
         data += length;
         length = 0;
      }
   }

   //Properly close output stream
   if(!level)
      error = httpCloseStream(connection);

   //Return status code
   return error;
}


/**
 * @brief Process SSI include directive
 *
 * This include directive allows the content of one document to be included
 * in another. The file parameter defines the included file as relative to
 * the document path. The virtual parameter defines the included file as
 * relative to the document root
 *
 * @param[in] connection Structure representing an HTTP connection
 * @param[in] tag Pointer to the SSI tag
 * @param[in] length Total length of the SSI tag
 * @param[in] uri NULL terminated string containing the file being processed
 * @param[in] level Current level of recursion
 * @return Error code
 **/

error_t ssiProcessIncludeCommand(HttpConnection *connection,
   const char_t *tag, size_t length, const char_t *uri, uint_t level)
{
   error_t error;
   uint8_t *data;
   char_t *separator;
   char_t *attribute;
   char_t *value;
   char_t *path;
   char_t *p;

   //Discard invalid SSI directives
   if(length < 7 || length >= HTTP_SERVER_BUFFER_SIZE)
      return ERROR_INVALID_TAG;

   //Skip the SSI include command (7 bytes)
   memcpy(connection->buffer, tag + 7, length - 7);
   //Ensure the resulting string is NULL-terminated
   connection->buffer[length - 7] = '\0';

   //Check whether a separator is present
   separator = strchr(connection->buffer, '=');
   //Separator not found?
   if(!separator)
      return ERROR_INVALID_TAG;

   //Split the tag
   *separator = '\0';

   //Get attribute name and value
   attribute = strTrimWhitespace(connection->buffer);
   value = strTrimWhitespace(separator + 1);

   //Remove leading simple or double quote
   if(value[0] == '\'' || value[0] == '\"')
      value++;

   //Get the length of the attribute value
   length = strlen(value);

   //Remove trailing simple or double quote
   if(length > 0)
   {
      if(value[length - 1] == '\'' || value[length - 1] == '\"')
         value[length - 1] = '\0';
   }

   //Check the length of the filename
   if(strlen(value) > HTTP_SERVER_URI_MAX_LEN)
      return ERROR_INVALID_TAG;

   //The file parameter defines the included file as relative to the document path
   if(!strcasecmp(attribute, "file"))
   {
      //Allocate a buffer to hold the path to the file to be included
      path = osMemAlloc(strlen(uri) + strlen(value) + 1);
      //Failed to allocate memory?
      if(!path) return ERROR_OUT_OF_MEMORY;

      //Copy the path identifying the script file being processed
      strcpy(path, uri);
      //Search for the last slash character
      p = strrchr(path, '/');

      //Remove the filename from the path if applicable
      if(p)
         strcpy(p + 1, value);
      else
         strcpy(path, value);
   }
   //The virtual parameter defines the included file as relative to the document root
   else if(!strcasecmp(attribute, "virtual"))
   {
      //Copy the absolute path
      path = strDuplicate(value);
      //Failed to duplicate the string?
      if(!path) return ERROR_OUT_OF_MEMORY;
   }
   //Unknown parameter...
   else
   {
      //Report an error
      return ERROR_INVALID_TAG;
   }

   //Use server-side scripting to dynamically generate HTML code?
   if(httpCompExtension(value, ".stm") ||
      httpCompExtension(value, ".shtm") ||
      httpCompExtension(value, ".shtml"))
   {
      //SSI processing (Server Side Includes)
      error = ssiExecuteScript(connection, path, level + 1);
   }
   else
   {
      //Get absolute path to the specified URI
      httpGetAbsolutePath(connection, path, connection->buffer);
      //Get the resource data associated with the file
      error = resGetData(connection->buffer, &data, &length);

      //Send the contents of the requested file
      if(!error)
         error = httpWriteStream(connection, data, length);
   }

   //Cannot found the specified resource?
   if(error == ERROR_NOT_FOUND)
      error = ERROR_INVALID_TAG;

   //Release previously allocated memory
   osMemFree(path);
   //return status code
   return error;
}


/**
 * @brief Process SSI echo directive
 *
 * This echo directive displays the contents of a specified
 * HTTP environment variable
 *
 * @param[in] connection Structure representing an HTTP connection
 * @param[in] tag Pointer to the SSI tag
 * @param[in] length Total length of the SSI tag
 * @return Error code
 **/

error_t ssiProcessEchoCommand(HttpConnection *connection, const char_t *tag, size_t length)
{
   error_t error;
   char_t *separator;
   char_t *attribute;
   char_t *value;

   //Discard invalid SSI directives
   if(length < 4 || length >= HTTP_SERVER_BUFFER_SIZE)
      return ERROR_INVALID_TAG;

   //Skip the SSI echo command (4 bytes)
   memcpy(connection->buffer, tag + 4, length - 4);
   //Ensure the resulting string is NULL-terminated
   connection->buffer[length - 4] = '\0';

   //Check whether a separator is present
   separator = strchr(connection->buffer, '=');
   //Separator not found?
   if(!separator)
      return ERROR_INVALID_TAG;

   //Split the tag
   *separator = '\0';

   //Get attribute name and value
   attribute = strTrimWhitespace(connection->buffer);
   value = strTrimWhitespace(separator + 1);

   //Remove leading simple or double quote
   if(value[0] == '\'' || value[0] == '\"')
      value++;

   //Get the length of the attribute value
   length = strlen(value);

   //Remove trailing simple or double quote
   if(length > 0)
   {
      if(value[length - 1] == '\'' || value[length - 1] == '\"')
         value[length - 1] = '\0';
   }

   //Enforce attribute name
   if(strcasecmp(attribute, "var"))
      return ERROR_INVALID_TAG;

   //Remote address?
   if(!strcasecmp(value, "REMOTE_ADDR"))
   {
      //The IP address of the host making this request
      ipAddrToString(&connection->socket->remoteIpAddr, connection->buffer);
   }
   //Remote port?
   else if(!strcasecmp(value, "REMOTE_PORT"))
   {
      //The port number used by the remote host when making this request
      sprintf(connection->buffer, "%u", connection->socket->remotePort);
   }
   //Server address?
   else if(!strcasecmp(value, "SERVER_ADDR"))
   {
      //The IP address of the server for this URL
      ipAddrToString(&connection->socket->localIpAddr, connection->buffer);
   }
   //Server port?
   else if(!strcasecmp(value, "SERVER_PORT"))
   {
      //The port number on this server to which this request was directed
      sprintf(connection->buffer, "%u", connection->socket->localPort);
   }
   //Request method?
   else if(!strcasecmp(value, "REQUEST_METHOD"))
   {
      //The method used for this HTTP request
      if(connection->request.method == HTTP_METHOD_GET)
         strcpy(connection->buffer, "GET");
      else if(connection->request.method == HTTP_METHOD_HEAD)
         strcpy(connection->buffer, "HEAD");
      else if(connection->request.method == HTTP_METHOD_POST)
         strcpy(connection->buffer, "POST");
      else
         connection->buffer[0] = '\0';
   }
   //Document URI?
   else if(!strcasecmp(value, "DOCUMENT_URI"))
   {
      //The URI for this request relative to the root directory
      strcpy(connection->buffer, connection->request.uri);
   }
   //Query string?
   else if(!strcasecmp(value, "QUERY_STRING"))
   {
      //The information following the "?" in the URL for this request
      strcpy(connection->buffer, connection->request.queryString);
   }
   //GMT time?
   else if(!strcasecmp(value, "DATE_GMT"))
   {
      //The current date and time in Greenwich Mean Time
      connection->buffer[0] = '\0';
   }
   //Local time?
   else if(!strcasecmp(value, "DATE_LOCAL"))
   {
      //The current date and time in the local timezone
      connection->buffer[0] = '\0';
   }
   //Unknown variable?
   else
   {
      //Report an error
      return ERROR_INVALID_TAG;
   }

   //Get the length of the resulting string
   length = strlen(connection->buffer);

   //Send the contents of the specified environment variable
   error = httpWriteStream(connection, connection->buffer, length);
   //Failed to send data?
   if(error) return error;

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Process SSI exec directive
 *
 * This exec directive executes a program, script, or shell command on
 * the server. The cmd parameter specifies a server-side command. The
 * cgi parameter specifies the path to a CGI script
 *
 * @param[in] connection Structure representing an HTTP connection
 * @param[in] tag Pointer to the SSI tag
 * @param[in] length Total length of the SSI tag
 * @return Error code
 **/

error_t ssiProcessExecCommand(HttpConnection *connection, const char_t *tag, size_t length)
{
   char_t *separator;
   char_t *attribute;
   char_t *value;

   //First, check whether CGI is supported by the server
   if(connection->settings->cgiCallback == NULL)
      return ERROR_INVALID_TAG;

   //Discard invalid SSI directives
   if(length < 4 || length >= HTTP_SERVER_BUFFER_SIZE)
      return ERROR_INVALID_TAG;

   //Skip the SSI exec command (4 bytes)
   memcpy(connection->buffer, tag + 4, length - 4);
   //Ensure the resulting string is NULL-terminated
   connection->buffer[length - 4] = '\0';

   //Check whether a separator is present
   separator = strchr(connection->buffer, '=');
   //Separator not found?
   if(!separator)
      return ERROR_INVALID_TAG;

   //Split the tag
   *separator = '\0';

   //Get attribute name and value
   attribute = strTrimWhitespace(connection->buffer);
   value = strTrimWhitespace(separator + 1);

   //Remove leading simple or double quote
   if(value[0] == '\'' || value[0] == '\"')
      value++;

   //Get the length of the attribute value
   length = strlen(value);

   //Remove trailing simple or double quote
   if(length > 0)
   {
      if(value[length - 1] == '\'' || value[length - 1] == '\"')
         value[length - 1] = '\0';
   }

   //Enforce attribute name
   if(strcasecmp(attribute, "cmd") && strcasecmp(attribute, "cgi"))
      return ERROR_INVALID_TAG;
   //Check the length of the CGI parameter
   if(strlen(value) > HTTP_SERVER_CGI_PARAM_MAX_LEN)
      return ERROR_INVALID_TAG;

   //The scratch buffer may be altered by the user-defined callback.
   //So the CGI parameter must be copied prior to function invocation
   strcpy(connection->cgiParam, value);

   //Invoke user-defined callback
   return connection->settings->cgiCallback(connection, connection->cgiParam);
}


/**
 * @brief Search a string for a given tag
 * @param[in] s String to search
 * @param[in] sLen Length of the string to search
 * @param[in] tag String containing the tag to search for
 * @param[in] tagLen Length of the tag
 * @return The index of the first occurrence of the tag in the string,
 *   or -1 if the tag does not appear in the string
 **/

int_t ssiSearchTag(const char_t *s, size_t sLen, const char_t *tag, size_t tagLen)
{
   size_t i;
   size_t j;

   //Loop through input string
   for(i = 0; (i + tagLen) <= sLen; i++)
   {
      //Compare current substring with the given tag
      for(j = 0; j < tagLen; j++)
      {
         if(s[i + j] != tag[j])
            break;
      }

      //Check whether the tag has been found
      if(j == tagLen)
         return i;
   }

   //The tag does not appear in the string
   return -1;
}

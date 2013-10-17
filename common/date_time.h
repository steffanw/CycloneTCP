/**
 * @file date_time.h
 * @brief Date and time management
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

#ifndef _DATE_TIME_H
#define _DATE_TIME_H

//Dependencies
#include "os.h"


/**
 * @brief Date and time representation
 **/

typedef struct
{
   uint16_t year;
   uint8_t month;
   uint8_t date;
   uint8_t day;
   uint8_t hours;
   uint8_t minutes;
   uint8_t seconds;
   int16_t timeZone;
} DateTime;

//Functions related to date and time management
void getCurrentDateTime(DateTime *dateTime);
uint32_t getCurrentUnixTime(void);

void unixTimeToDateTime(uint32_t unixTime, DateTime *dateTime);
uint32_t dateTimeToUnixTime(const DateTime *dateTime);

uint8_t computeDayOfWeek(uint16_t y, uint8_t m, uint8_t d);

#endif

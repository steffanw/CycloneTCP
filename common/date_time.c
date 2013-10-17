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

#include "date_time.h"


/**
 * @brief Calculate day of week
 * @param[in] y Year
 * @param[in] m Month of year (in range 1 to 12)
 * @param[in] d Day of month (in range 1 to 31)
 * @return Day of week (in range 1 to 7)
 **/

uint8_t computeDayOfWeek(uint16_t y, uint8_t m, uint8_t d)
{
   uint_t h;
   uint_t j;
   uint_t k;

   //January and February are counted as months 13 and 14 of the previous year
   if(m <= 2)
   {
      m += 12;
      y -= 1;
   }

   //J is the century
   j = y / 100;
   //K the year of the century
   k = y % 100;

   //Compute H using Zeller's congruence
   h = d + (26 * (m + 1) / 10) + k + (k / 4) + (5 * j) + (j / 4);

   //Return the day of the week
   return ((h + 5) % 7) + 1;
}

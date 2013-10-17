/**
 * @file mpi.c
 * @brief MPI (Multiple Precision Integer Arithmetic)
 *
 * @section License
 *
 * Copyright (C) 2010-2013 Oryx Embedded. All rights reserved.
 *
 * This file is part of CycloneCrypto Open.
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
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "mpi.h"
#include "debug.h"


/**
 * @brief Initialize a big number
 * @param[in,out] x Pointer to the multiple precision integer to initialize
 **/

void mpiInit(Mpi *x)
{
   //Initialize structure
   x->sign = 1;
   x->size = 0;
   x->data = NULL;
}


/**
 * @brief Release a big number
 * @param[in,out] x Pointer to the multiple precision integer to free
 **/

void mpiFree(Mpi *x)
{
   //Any memory previously allocated?
   if(x->data != NULL)
   {
      //Erase contents before releasing memory
      memset(x->data, 0, x->size * MPI_INT_SIZE);
      osMemFree(x->data);
   }
   //Set size to zero
   x->size = 0;
   x->data = NULL;
}


/**
 * @brief Adjust the size of a big number
 * @param[in,out] x Pointer to a multiple precision integer
 * @param[in] size Desired size
 * @return Error code
 **/

error_t mpiGrow(Mpi *x, uint_t size)
{
   uint_t *data;

   //Check the current size
   if(x->size >= size)
      return NO_ERROR;

   //Allocate a memory buffer
   data = osMemAlloc(size * MPI_INT_SIZE);
   //Failed to allocate memory?
   if(!data) return ERROR_OUT_OF_MEMORY;
   //Clear buffer contents
   memset(data, 0, size * MPI_INT_SIZE);

   //Any data to copy?
   if(x->size > 0)
   {
      //Copy original data
      memcpy(data, x->data, x->size * MPI_INT_SIZE);
      //Free previously allocated memory
      osMemFree(x->data);
   }

   //Update the size of the multiple precision integer
   x->size = size;
   x->data = data;

   //Successful operation
   return NO_ERROR;
}


/**
 * @brief Get the actual length
 * @param[in] a Pointer to a multiple precision integer
 * @return The actual length in words
 **/

uint_t mpiGetLength(const Mpi *a)
{
   int_t i;

   //Check whether the specified multiple precision integer is empty
   if(a->size == 0) return 0;

   //Start from the most significant word
   for(i = a->size - 1; i >= 0; i--)
   {
      //Loop as long as the current word is zero
      if(a->data[i] != 0) break;
   }

   //Return the actual length
   return i + 1;
}


/**
 * @brief Get the actual length in bytes
 * @param[in] a Pointer to a multiple precision integer
 * @return The actual byte count
 **/

uint_t mpiGetByteLength(const Mpi *a)
{
   uint_t n;
   uint32_t m;

   //Check whether the specified multiple precision integer is empty
   if(a->size == 0) return 0;

   //Start from the most significant word
   for(n = a->size - 1; n > 0; n--)
   {
      //Loop as long as the current word is zero
      if(a->data[n] != 0)
         break;
   }

   //Get the current word
   m = a->data[n];
   //Convert the length to a byte count
   n *= MPI_INT_SIZE;

   //Adjust the byte count
   for(; m != 0; m >>= 8) n++;

   //Return the actual length in bytes
   return n;
}


/**
 * @brief Get the actual length in bits
 * @param[in] a Pointer to a multiple precision integer
 * @return The actual bit count
 **/

uint_t mpiGetBitLength(const Mpi *a)
{
   uint_t n;
   uint32_t m;

   //Check whether the specified multiple precision integer is empty
   if(a->size == 0) return 0;

   //Start from the most significant word
   for(n = a->size - 1; n > 0; n--)
   {
      //Loop as long as the current word is zero
      if(a->data[n] != 0)
         break;
   }

   //Get the current word
   m = a->data[n];
   //Convert the length to a bit count
   n *= MPI_INT_SIZE * 8;

   //Adjust the bit count
   for(; m != 0; m >>= 1) n++;

   //Return the actual length in bits
   return n;
}


/**
 * @brief Set the bit value at the specified index
 * @param[in] x Pointer to a multiple precision integer
 * @param[in] index Position of the bit to write
 * @param[in] value Bit value
 * @return Error code
 **/

error_t mpiSetBitValue(Mpi *x, uint_t index, uint_t value)
{
   error_t error;

   uint_t n1 = index / (MPI_INT_SIZE * 8);
   uint_t n2 = index % (MPI_INT_SIZE * 8);

   //Ajust the size of the big number if necessary
   error = mpiGrow(x, (index + (MPI_INT_SIZE * 8) - 1) / (MPI_INT_SIZE * 8));
   //Failed to adjust the size?
   if(error) return error;

   //Set bit value
   if(value)
      x->data[n1] |= (1 << n2);
   else
      x->data[n1] &= ~(1 << n2);

   //No error to report
   return NO_ERROR;
}


/**
 * @brief Get the bit value at the specified index
 * @param[in] a Pointer to a multiple precision integer
 * @param[in] index Position where to read the bit
 * @return The actual bit value
 **/

uint_t mpiGetBitValue(const Mpi *a, uint_t index)
{
   uint_t n1 = index / (MPI_INT_SIZE * 8);
   uint_t n2 = index % (MPI_INT_SIZE * 8);

   //Index out of range?
   if(n1 >= a->size)
      return 0;

   //Return the actual bit value
   return (a->data[n1] >> n2) & 0x01;
}


/**
 * @brief Comparison between two big numbers
 * @param[in] a Pointer to the first multiple precision integer
 * @param[in] b Pointer to the second multiple precision integer
 * @return Comparison result
 **/

int_t mpiComp(const Mpi *a, const Mpi *b)
{
   uint_t m;
   uint_t n;

   //Determine the actual length of A and B
   m = mpiGetLength(a);
   n = mpiGetLength(b);

   //Compare length
   if(!m && !n)
      return 0;
   else if(m > n)
      return a->sign;
   else if(m < n)
      return -b->sign;

   //Compare sign
   if(a->sign > 0 && b->sign < 0)
      return 1;
   else if(a->sign < 0 && b->sign > 0)
      return -1;

   //Compare values
   while(n--)
   {
      if(a->data[n] > b->data[n])
         return a->sign;
      else if(a->data[n] < b->data[n])
         return -a->sign;
   }

   //Operands are equals
   return 0;
}


/**
 * @brief Comparison between a big number and an integer
 * @param[in] a Pointer to the multiple precision integer
 * @param[in] b Value to compare
 * @return Comparison result
 **/

int_t mpiCompInt(const Mpi *a, int_t b)
{
   uint_t value;
   Mpi x;

   //Initialize a temporary multiple precision integer
   value = (b >= 0) ? b : -b;
   x.sign = (b >= 0) ? 1 : -1;
   x.size = 1;
   x.data = &value;

   //Return comparison result
   return mpiComp(a, &x);
}


/**
 * @brief Comparison the absolute value of two big numbers
 * @param[in] a Pointer to the first multiple precision integer
 * @param[in] b Pointer to the second multiple precision integer
 * @return Comparison result
 **/

int_t mpiCompAbs(const Mpi *a, const Mpi *b)
{
   uint_t m;
   uint_t n;

   //Determine the actual length of A and B
   m = mpiGetLength(a);
   n = mpiGetLength(b);

   //Compare length
   if(!m && !n)
      return 0;
   else if(m > n)
      return 1;
   else if(m < n)
      return -1;

   //Compare values
   while(n--)
   {
      if(a->data[n] > b->data[n])
         return 1;
      else if(a->data[n] < b->data[n])
         return -1;
   }

   //Operands are equals
   return 0;
}


/**
 * @brief Copy a big number
 * @param[out] x Pointer to a multiple precision integer
 * @param[in] a Value to assign to the big number
 * @return Error code
 **/

error_t mpiCopy(Mpi *x, const Mpi *a)
{
   error_t error;
   uint_t n;

   if(x == a)
      return NO_ERROR;

   //Determine the actual length of A
   n = mpiGetLength(a);
   //Ajust the size of the destination operand
   error = mpiGrow(x, n);
   //Any error to report?
   if(error) return error;
   //Clear contents
   memset(x->data, 0, x->size * MPI_INT_SIZE);

   //Copy the sign of A
   x->sign = a->sign;
   //Copy the value of A
   memcpy(x->data, a->data, n * MPI_INT_SIZE);

   //Successful operation
   return NO_ERROR;
}


/**
 * @brief Set the value of a big number
 * @param[out] x Pointer to a multiple precision integer
 * @param[in] a Value to assign to the big number
 * @return Error code
 **/

error_t mpiSetValue(Mpi *x, int_t a)
{
   error_t error;

   //Ajust the size of the big number if necessary
   error = mpiGrow(x, 1);
   //Failed to adjust the size?
   if(error) return error;

   //Clear big number contents
   memset(x->data, 0, x->size * MPI_INT_SIZE);

   //Set sign
   x->sign = (a >= 0) ? 1 : -1;
   //Set value
   x->data[0] = (a >= 0) ? a : -a;

   //Successful operation
   return NO_ERROR;
}


/**
 * @brief Generate a random value
 * @param[out] x Pointer to a multiple precision integer
 * @param[in] length Desired length in bits
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t mpiRand(Mpi *x, uint_t length, const PrngAlgo *prngAlgo, void *prngContext)
{
   error_t error;
   uint_t m;
   uint_t n;

   //Compute the required length, in words
   n = (length + (MPI_INT_SIZE * 8) - 1) / (MPI_INT_SIZE * 8);
   //Number of bits in the most significant word
   m = length % (MPI_INT_SIZE * 8);

   //Ajust the size of the big number if necessary
   error = mpiGrow(x, n);
   //Failed to adjust the size?
   if(error) return error;

   //Set sign
   x->sign = 1;

   //Generate random data
   error = prngAlgo->read(prngContext, (uint8_t *) x->data, n * MPI_INT_SIZE);
   //Any error to report?
   if(error) return error;

   //Remove the meaningless bits in the most significant word
   if(n > 0 && m > 0)
      x->data[n - 1] &= (1 << m) - 1;

   //Successful operation
   return NO_ERROR;
}


/**
 * @brief Octet string to integer conversion
 *
 * Converts an octet string to a non-negative integer
 *
 * @param[out] x Non-negative integer resulting from the conversion
 * @param[in] data Octet string to be converted
 * @param[in] length Length of the octet string
 * @return Error code
 **/

error_t mpiReadRaw(Mpi *x, const uint8_t *data, uint_t length)
{
   error_t error;
   uint_t i;
   uint8_t *p;

   //Skip leading zeroes
   while(length > 1 && *data == 0)
   {
      data++;
      length--;
   }

   //Ajust the size of the big integer
   error = mpiGrow(x, (length + MPI_INT_SIZE - 1) / MPI_INT_SIZE);
   //Failed to adjust the size?
   if(error) return error;

   //Set sign
   x->sign = 1;
   //Clear big integer contents
   memset(x->data, 0, x->size * MPI_INT_SIZE);

   //Cast the big integer to byte array
   p = (uint8_t *) x->data;

   //Start from the least significant word
   for(i = 0; i < length; i++)
      p[i] = data[length - 1 - i];

   //The conversion succeeded
   return NO_ERROR;
}


/**
 * @brief Integer to octet string conversion
 *
 * Converts an integer to an octet string of a specified length
 *
 * @param[in] a Non-negative integer to be converted
 * @param[out] data Octet string resulting from the conversion
 * @param[in] length Intended length of the resulting octet string
 * @return Error code
 **/

error_t mpiWriteRaw(const Mpi *a, uint8_t *data, uint_t length)
{
   uint_t i;
   uint8_t *p;

   //Get the actual length in bytes
   uint_t n = mpiGetByteLength(a);

   //Make sure the output buffer is large enough
   if(n > length)
      return ERROR_INVALID_LENGTH;

   //Cast the big integer to byte array
   p = (uint8_t *) a->data;

   //Clear output buffer
   memset(data, 0, length);
   //Start from the least significant word
   for(i = 0; i < n; i++)
      data[length - 1 - i] = p[i];

   //The conversion succeeded
   return NO_ERROR;
}


/**
 * @brief Multiple precision addition
 * @param[out] x Resulting sum A+B
 * @param[in] a First operand
 * @param[in] b Second operand
 * @return Error code
 **/

error_t mpiAdd(Mpi *x, const Mpi *a, const Mpi *b)
{
   error_t error;

   //Both operands have the same sign?
   if(a->sign == b->sign)
   {
      //Perform addition
      error = mpiAddAbs(x, a, b);
      //Set the sign of the resulting number
      x->sign = a->sign;
   }
   //Operands have different signs?
   else
   {
      //Compare the absolute value of A and B
      if(mpiCompAbs(a, b) >= 0)
      {
         //Perform subtraction
         error = mpiSubAbs(x, a, b);
         //Set the sign of the resulting number
         x->sign = a->sign;
      }
      else
      {
         //Perform subtraction
         error = mpiSubAbs(x, b, a);
         //Set the sign of the resulting number
         x->sign = b->sign;
      }
   }

   //Return status code
   return error;
}


/**
 * @brief Add an integer to a multiple precision number
 * @param[out] x Resulting sum A+B
 * @param[in] a First operand
 * @param[in] b Second operand
 * @return Error code
 **/

error_t mpiAddInt(Mpi *x, const Mpi *a, int_t b)
{
   uint_t value;
   Mpi c;

   //Convert the second operand to a multiple precision number
   value = (b >= 0) ? b : -b;
   c.sign = (b >= 0) ? 1 : -1;
   c.size = 1;
   c.data = &value;

   //Perform addition
   return mpiAdd(x, a ,&c);
}


/**
 * @brief Multiple precision subtraction
 * @param[out] x Resulting difference A-B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiSub(Mpi *x, const Mpi *a, const Mpi *b)
{
   error_t error;

   //Both operands have the same sign?
   if(a->sign == b->sign)
   {
      //Compare the absolute value of A and B
      if(mpiCompAbs(a, b) >= 0)
      {
         //Perform subtraction
         error = mpiSubAbs(x, a, b);
         //Set the sign of the resulting number
         x->sign = a->sign;
      }
      else
      {
         //Perform subtraction
         error = mpiSubAbs(x, b, a);
         //Set the sign of the resulting number
         x->sign = -a->sign;
      }
   }
   //Operands have different signs?
   else
   {
      //Perform addition
      error = mpiAddAbs(x, a, b);
      //Set the sign of the resulting number
      x->sign = a->sign;
   }

   //Return status code
   return error;
}


/**
 * @brief Subtract an integer from a multiple precision number
 * @param[out] x Resulting sum A+B
 * @param[in] a First operand
 * @param[in] b Second operand
 * @return Error code
 **/

error_t mpiSubInt(Mpi *x, const Mpi *a, int_t b)
{
   uint_t value;
   Mpi c;

   //Convert the second operand to a multiple precision number
   value = (b >= 0) ? b : -b;
   c.sign = (b >= 0) ? 1 : -1;
   c.size = 1;
   c.data = &value;

   //Perform subtraction
   return mpiSub(x, a ,&c);
}


/**
 * @brief Helper routine for multiple precision addition
 * @param[out] x Resulting sum A+B
 * @param[in] a First operand
 * @param[in] b Second operand
 * @return Error code
 **/

error_t mpiAddAbs(Mpi *x, const Mpi *a, const Mpi *b)
{
   error_t error;
   uint_t i;
   uint_t n;
   uint_t c;

   //The destination operand is B?
   if(x == b)
   {
      //Swap A and B
      const Mpi *t = b;
      a = b;
      b = t;
   }
   //The destination operand is neither A nor B?
   else if(x != a)
   {
      //Copy the first operand to X
      error = mpiCopy(x, a);
      //Any error to report?
      if(error) return error;
   }

   //Determine the actual length of B
   n = mpiGetLength(b);
   //Extend the size of the destination register as needed
   error = mpiGrow(x, n);
   //Any error to report?
   if(error) return error;

   //The result is always positive
   x->sign = 1;
   //Clear carry bit
   c = 0;

   //Add operands
   for(i = 0; i < n; i++)
   {
      //Add carry bit
      x->data[i] += c;
      //Update carry bit
      if(x->data[i] != 0) c = 0;
      //Perform addition
      x->data[i] += b->data[i];
      //Update carry bit
      if(x->data[i] < b->data[i]) c = 1;
   }

   //Loop as long as the carry bit is set
   for(i = n; c && i < x->size; i++)
   {
      //Add carry bit
      x->data[i] += c;
      //Update carry bit
      if(x->data[i] != 0) c = 0;
   }

   //Check the final carry bit
   if(c && n >= x->size)
   {
      //Extend the size of the destination register
      error = mpiGrow(x, n + 1);
      //Any error to report?
      if(error) return error;
      //Add carry bit
      x->data[n] = 1;
   }

   //Successful operation
   return NO_ERROR;
}


/**
 * @brief Helper routine for multiple precision subtraction
 * @param[out] x Resulting difference A-B
 * @param[in] a First operand A
 * @param[in] b Second operand B
 * @return Error code
 **/

error_t mpiSubAbs(Mpi *x, const Mpi *a, const Mpi *b)
{
   error_t error;
   uint_t i;
   uint_t n;
   uint_t c;
   Mpi d;

   //Initialize D
   mpiInit(&d);

   //Check input parameters
   if(mpiCompAbs(a, b) < 0)
   {
      //Swap A and B if necessary
      const Mpi *t = b;
      a = b;
      b = t;
   }

   //The destination operand is B?
   if(x == b)
   {
      //Copy B operand to D
      error = mpiCopy(&d, b);
      //Any error to report?
      if(error) return error;
      //Use D instead of B
      b = &d;
      //Copy the first operand to X
      mpiCopy(x, a);
   }
   //The destination operand is neither A nor B?
   else if(x != a)
   {
      //Copy the first operand to X
      mpiCopy(x, a);
   }

   //Determine the actual length of B
   n = mpiGetLength(b);
   //The result is always positive
   x->sign = 1;
   //Clear carry bit
   c = 0;

   //Subtract operands
   for(i = 0; i < n; i++)
   {
      //Check the carry bit
      if(c)
      {
         //Update carry bit
         if(x->data[i] != 0) c = 0;
         //Subtract carry bit
         x->data[i] -= 1;
      }
      //Update carry bit
      if(x->data[i] < b->data[i])
         c = 1;
      //Perform subtraction
      x->data[i] -= b->data[i];
   }

   //Loop as long as the carry bit is set
   for(i = n; c && i < x->size; i++)
   {
      //Update carry bit
      if(x->data[i] != 0) c = 0;
      //Subtract carry bit
      x->data[i] -= 1;

   }

   //Release previously allocated memory
   mpiFree(&d);
   //Successful operation
   return NO_ERROR;
}


/**
 * @brief Shift a big integer a specified number of bits to the left
 * @param[in,out] x Pointer to a multiple precision integer
 * @param[in] n The number of bits to shift value to the left
 * @return Error code
 **/

error_t mpiShiftLeft(Mpi *x, uint_t n)
{
   error_t error;
   uint_t i;

   //Number of 32-bit words to shift
   uint_t n1 = n / (MPI_INT_SIZE * 8);
   //Number of bits to shift
   uint_t n2 = n % (MPI_INT_SIZE * 8);

   //Check parameters
   if(!x->size || !n)
      return NO_ERROR;

   //Increase the size of the multiple-precision number
   error = mpiGrow(x, x->size + (n + 31) / 32);
   //Check return code
   if(error) return error;

   //First, shift words
   if(n1 > 0)
   {
      //Process the most significant words
      for(i = x->size - 1; i >= n1; i--)
         x->data[i] = x->data[i - n1];
      //Fill the rest with zeroes
      for(i = 0; i < n1; i++)
         x->data[i] = 0;
   }
   //Then shift bits
   if(n2 > 0)
   {
      //Process the most significant words
      for(i = x->size - 1; i >= 1; i--)
         x->data[i] = (x->data[i] << n2) | (x->data[i - 1] >> (32 - n2));
      //The least significant word requires a special handling
      x->data[0] <<= n2;
   }

   //Shift operation is complete
   return NO_ERROR;
}


/**
 * @brief Shift a big integer a specified number of bits to the right
 * @param[in,out] x Pointer to a multiple precision integer
 * @param[in] n The number of bits to shift value to the right
 * @return Error code
 **/

error_t mpiShiftRight(Mpi *x, uint_t n)
{
   uint_t i;
   uint_t m;

   //Number of 32-bit words to shift
   uint_t n1 = n / (MPI_INT_SIZE * 8);
   //Number of bits to shift
   uint_t n2 = n % (MPI_INT_SIZE * 8);

   //Check parameters
   if(n1 >= x->size)
   {
      memset(x->data, 0, x->size * MPI_INT_SIZE);
      return NO_ERROR;
   }

   //First, shift words
   if(n1 > 0)
   {
      //Process the least significant words
      for(m = x->size - n1, i = 0; i < m; i++)
         x->data[i] = x->data[i + n1];
      //Fill the rest with zeroes
      for(i = m; i < x->size; i++)
         x->data[i] = 0;
   }
   //Then shift bits
   if(n2 > 0)
   {
      //Process the least significant words
      for(m = x->size - n1 - 1, i = 0; i < m; i++)
         x->data[i] = (x->data[i] >> n2) | (x->data[i + 1] << (32 - n2));
      //The most significant word requires a special handling
      x->data[m] >>= n2;
   }

   //Shift operation is complete
   return NO_ERROR;
}


#define ADDC(x, a, c) \
   x += c; \
   if((x) != 0) c = 0; \
   x += a; \
   if((x) < (a)) c = 1

error_t mpiMul(Mpi *x, const Mpi *a, const Mpi *b)
{
   error_t error;
   int_t i;
   int_t k;
   int_t m;
   int_t n;
   uint64_t p;
   Mpi ta;
   Mpi tb;

   mpiInit(&ta);
   mpiInit(&tb);

   if(x == a)
   {
      //Copy A to TA
      error = mpiCopy(&ta, a);
      //Any error to report?
      if(error) return error;
      //Use TA instead of A
      a = &ta;
   }
   if(x == b)
   {
      //Copy B to TB
      error = mpiCopy(&tb, b);
      //Any error to report?
      if(error)
      {
         //Free previously allocated memory
         mpiFree(&ta);
         return error;
      }
      //Use TB instead of B
      b = &tb;
   }

   //Determine the actual length of A and B
   m = mpiGetLength(a);
   n = mpiGetLength(b);

   //Adjust the size of the destination operand
   error = mpiGrow(x, m + n);
   //Any error to report?
   if(error)
   {
      //Free previously allocated memory
      mpiFree(&ta);
      mpiFree(&tb);
      return error;
   }

   //Set the sign of the result X
   x->sign = (a->sign == b->sign) ? 1 : -1;
   //Clear the contents of X
   memset(x->data, 0, x->size * MPI_INT_SIZE);

   for(k = 0; k <= (m + n - 2); k++)
   {
      for(i = max(k - n + 1, 0); i <= min(k, m - 1); i++)
      {
         uint_t c = 0;
         p = (uint64_t) a->data[i] * b->data[k - i];
         ADDC(x->data[k], (uint32_t ) p, c);
         ADDC(x->data[k + 1], (uint32_t) (p >> 32), c);
         ADDC(x->data[k + 2], 0, c);
      }
   }

   //Release previously allocated memory
   mpiFree(&ta);
   mpiFree(&tb);
   //Successful operation
   return NO_ERROR;
}

error_t mpiMulInt(Mpi *x, const Mpi *a, int_t b)
{
   uint_t value;
   Mpi c;

   value = (b >= 0) ? b : -b;
   c.sign = (b >= 0) ? 1 : -1;
   c.size = 1;
   c.data = &value;

   return mpiMul(x, a, &c);
}


error_t mpiDiv(Mpi *x, Mpi *y, const Mpi *a, const Mpi *b)
{
   error_t error;
   uint_t m;
   uint_t n;
   Mpi c;
   Mpi d;
   Mpi e;

   if(!mpiCompInt(b, 0))
      return ERROR_INVALID_PARAMETER;

   //Initialize multiple precision integers
   mpiInit(&c);
   mpiInit(&d);
   mpiInit(&e);

   MPI_CHECK(mpiCopy(&c, a));
   MPI_CHECK(mpiCopy(&d, b));
   MPI_CHECK(mpiSetValue(&e, 0));

   m = mpiGetBitLength(&c);
   n = mpiGetBitLength(&d);

   if(m > n)
      MPI_CHECK(mpiShiftLeft(&d, m - n));

   while(n++ <= m)
   {
      MPI_CHECK(mpiShiftLeft(&e, 1));

      if(mpiComp(&c, &d) >= 0)
      {
         MPI_CHECK(mpiSetBitValue(&e, 0, 1));
         MPI_CHECK(mpiSub(&c, &c, &d));
      }

      MPI_CHECK(mpiShiftRight(&d, 1));
   }

   if(x != NULL)
      MPI_CHECK(mpiCopy(x, &e));

   if(y != NULL)
      MPI_CHECK(mpiCopy(y, &c));

end:

   //Release previously allocated memory
   mpiFree(&c);
   mpiFree(&d);
   mpiFree(&e);

   //Return status code
   return error;
}


error_t mpiDivInt(Mpi *x, Mpi *y, const Mpi *a, int_t b)
{
   uint_t value;
   Mpi c;

   value = (b >= 0) ? b : -b;
   c.sign = (b >= 0) ? 1 : -1;
   c.size = 1;
   c.data = &value;

   return mpiDiv(x, y, a, &c);
}


error_t mpiMod(Mpi *x, const Mpi *a, const Mpi *b)
{
   error_t error;
   int_t sign;
   uint_t m;
   uint_t n;
   Mpi c;

   //Make sure the modulus is positive
   if(mpiCompInt(b, 0) <= 0)
      return ERROR_INVALID_PARAMETER;

   sign = a->sign;
   m = mpiGetBitLength(a);
   n = mpiGetBitLength(b);

   if(m < n) return NO_ERROR;

   //Initialize multiple precision integer
   mpiInit(&c);

   MPI_CHECK(mpiCopy(&c, b));
   MPI_CHECK(mpiShiftLeft(&c, m - n));
   MPI_CHECK(mpiCopy(x, a));

   while(mpiCompAbs(x, b) >= 0)
   {
      if(mpiCompAbs(x, &c) >= 0)
      {
         MPI_CHECK(mpiSubAbs(x, x, &c));
      }

      MPI_CHECK(mpiShiftRight(&c, 1));
   }

   if(sign < 0)
   {
      MPI_CHECK(mpiSubAbs(x, b, x));
   }

end:
   //Release previously allocated memory
   mpiFree(&c);
   //Return status code
   return NO_ERROR;
}


error_t mpiMulMod(Mpi *x, const Mpi *a, const Mpi *b, const Mpi *p)
{
   error_t error;

   //Perform modular multiplication
   MPI_CHECK(mpiMul(x, a, b));
   MPI_CHECK(mpiMod(x, x, p));

end:
   //Return status code
   return error;
}


error_t mpiInvMod(Mpi *x, const Mpi *a, const Mpi *p)
{
   error_t error;
   Mpi b;
   Mpi c;
   Mpi q;
   Mpi r;
   Mpi t;
   Mpi u;
   Mpi v;

   //Initialize multiple precision integers
   mpiInit(&b);
   mpiInit(&c);
   mpiInit(&q);
   mpiInit(&r);
   mpiInit(&t);
   mpiInit(&u);
   mpiInit(&v);

   MPI_CHECK(mpiCopy(&b, p));
   MPI_CHECK(mpiCopy(&c, a));
   MPI_CHECK(mpiSetValue(&u, 0));
   MPI_CHECK(mpiSetValue(&v, 1));

   while(mpiCompInt(&c, 0) > 0)
   {
      MPI_CHECK(mpiDiv(&q, &r, &b, &c));

      MPI_CHECK(mpiCopy(&b, &c));
      MPI_CHECK(mpiCopy(&c, &r));

      MPI_CHECK(mpiCopy(&t, &v));
      MPI_CHECK(mpiMul(&q, &q, &v));
      MPI_CHECK(mpiSub(&v, &u, &q));
      MPI_CHECK(mpiCopy(&u, &t));
   }

   if(mpiCompInt(&b, 1))
   {
      MPI_CHECK(ERROR_FAILURE);
   }

   if(mpiCompInt(&u, 0) > 0)
   {
      MPI_CHECK(mpiCopy(x, &u));
   }
   else
   {
      MPI_CHECK(mpiAdd(x, &u, p));
   }

end:
   //Release previously allocated memory
   mpiFree(&b);
   mpiFree(&c);
   mpiFree(&q);
   mpiFree(&r);
   mpiFree(&t);
   mpiFree(&u);
   mpiFree(&v);

   //Return status code
   return error;
}


error_t mpiExpMod(Mpi *x, const Mpi *a, const Mpi *e, const Mpi *p)
{
   error_t error;
   int_t i;
   uint_t k;
   Mpi b;
   Mpi y;
   Mpi r2;

   //Initialize multiple precision integers
   mpiInit(&b);
   mpiInit(&y);
   mpiInit(&r2);

   if(mpiIsEven(p))
   {
      if(x == a)
      {
         MPI_CHECK(mpiCopy(&b, a));
         a = &b;
      }

      MPI_CHECK(mpiSetValue(x, 1));

      for(i = mpiGetBitLength(e) - 1; i >= 0; i--)
      {
         MPI_CHECK(mpiMulMod(x, x, x, p));

         if(mpiGetBitValue(e, i))
         {
            MPI_CHECK(mpiMulMod(x, x, a, p));
         }
      }
   }
   else
   {
      //Compute the smaller R = (2^32)^k such as R > P
      k = mpiGetLength(p);

      //Compute R^2 mod P
      MPI_CHECK(mpiSetValue(&r2, 1));
      MPI_CHECK(mpiShiftLeft(&r2, 2 * k * (MPI_INT_SIZE * 8)));
      MPI_CHECK(mpiMod(&r2, &r2, p));

      //Compute B = A * R mod P
      if(mpiComp(a, p) >= 0)
      {
         MPI_CHECK(mpiMod(&b, a, p));
         MPI_CHECK(mpiMontgomeryMul(&b, &b, &r2, k, p));
      }
      else
      {
         MPI_CHECK(mpiMontgomeryMul(&b, a, &r2, k, p));
      }

      //Compute X = R mod P
      MPI_CHECK(mpiCopy(&y, &r2));
      MPI_CHECK(mpiMontgomeryRed(&y, k, p));

      for(i = mpiGetBitLength(e) - 1; i >= 0; i--)
      {
         //Compute X = X^2 * R^-1 mod P
         MPI_CHECK(mpiMontgomeryMul(&y, &y, &y, k, p));

         if(mpiGetBitValue(e, i))
         {
            //Compute X = X * B * R^-1 mod P
            MPI_CHECK(mpiMontgomeryMul(&y, &y, &b, k, p));
         }
      }

      //Compute X = X * R^-1 mod N
      MPI_CHECK(mpiMontgomeryRed(&y, k, p));
      MPI_CHECK(mpiCopy(x, &y));
   }

end:
   //Release multiple precision integers
   mpiFree(&b);
   mpiFree(&y);
   mpiFree(&r2);

   //Return status code
   return error;
}


/**
 * @brief Montgomery multiplication (X = A * B / 2^k mod P)
 **/

error_t mpiMontgomeryMul(Mpi *x, const Mpi *a, const Mpi *b, uint_t k, const Mpi *p)
{
   error_t error;

   //Perform Montgomery multiplication
   MPI_CHECK(mpiMul(x, a, b));
   MPI_CHECK(mpiMontgomeryRed(x, k, p));

end:
   //Return status code
   return error;
}


/**
 * @brief Montgomery reduction (X = X / 2^k mod P)
 * @param[in,out] x Pointer to a multiple precision integer
 * @param[in] k
 * @param[in] p
 * @return Error code
 **/

error_t mpiMontgomeryRed(Mpi *x, uint_t k, const Mpi *p)
{
#if 0
   Mpi r, rinv;

   //Compute R mod N
   mpiInit(&r);
   mpiSetValue(&r, 1);
   mpiShiftLeft(&r, k * (MPI_INT_SIZE * 8));
   mpiMod(&r, &r, p);

   //Compute R^-1 mod N
   mpiInit(&rinv);
   mpiInvMod(&rinv, &r, p);

   mpiMul(x, x, &rinv);
   mpiMod(x, x, p);

   return NO_ERROR;
#else
   error_t error;
   uint_t i;
   uint32_t m;
   Mpi ll;

   //Initialize multiple precision integer
   mpiInit(&ll);

   //Use Newton's method to compute the inverse of P[0] mod 2^32
   for(m = 2 - p->data[0], i = 0; i < 4; i++)
         m = m * (2 - m * p->data[0]);

   //Precompute -1/P[0] mod 2^32;
   m = ~m + 1;

   for(i = 0; i < k; i++)
   {
      MPI_CHECK(mpiSetValue(&ll, 1));
      ll.data[0] = x->data[0] * m;

      MPI_CHECK(mpiMul(&ll, p, &ll));
      MPI_CHECK(mpiAdd(x, x, &ll));
      MPI_CHECK(mpiShiftRight(x, MPI_INT_SIZE * 8));
   }

   if(mpiComp(x, p) >= 0)
   {
      MPI_CHECK(mpiSub(x, x, p));
   }

end:
   //Release multiple precision integer
   mpiFree(&ll);
   //Return status code
   return error;
#endif
}


/**
 * @brief Display the contents of a big number
 * @param[in] stream Pointer to a FILE object that identifies an output stream
 * @param[in] prepend String to prepend to the left of each line
 * @param[in] a Pointer to the multiple precision integer to dump
 **/

void mpiDump(FILE *stream, const char_t *prepend, const Mpi *a)
{
   uint_t i;

   //Process each word
   for(i = 0; i < a->size; i++)
   {
      //Beginning of a new line?
      if(i == 0 || ((a->size - i - 1) % 8) == 7)
         fputs(prepend, stream);
      //Display current data
      fprintf(stream, "%08X ", a->data[a->size - 1 - i]);
      //End of current line?
      if(!((a->size - i - 1) % 8) || i == (a->size - 1))
         fprintf(stream, "\r\n");
   }
}

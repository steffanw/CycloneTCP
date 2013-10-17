/**
 * @file dh.c
 * @brief Diffie-Hellman key exchange
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
 * @section Description
 *
 * The Diffie-Hellman key agreement protocol allows two users to exchange a
 * secret key over an insecure medium without any prior secrets. Refer to
 * PKCS #3 (Diffie-Hellman Key-Agreement Standard)
 *
 * @author Oryx Embedded (www.oryx-embedded.com)
 * @version 1.3.8
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include <stdlib.h>
#include "crypto.h"
#include "dh.h"
#include "debug.h"


/**
 * @brief Initialize Diffie-Hellman parameters
 * @param[in] params Pointer to the Diffie-Hellman parameters
 **/

void dhInitParameters(DhParameters *params)
{
   //Initialize multiple precision integers
   mpiInit(&params->p);
   mpiInit(&params->g);
   mpiInit(&params->xa);
   mpiInit(&params->ya);
   mpiInit(&params->yb);
}


/**
 * @brief Release Diffie-Hellman parameters
 * @param[in] params Pointer to the Diffie-Hellman parameters
 **/

void dhFreeParameters(DhParameters *params)
{
   //Free multiple precision integers
   mpiFree(&params->p);
   mpiFree(&params->g);
   mpiFree(&params->xa);
   mpiFree(&params->ya);
   mpiFree(&params->yb);
}


/**
 * @brief Diffie-Hellman key pair generation
 * @param[in,out] params Pointer to the Diffie-Hellman parameters
 * @param[in] prngAlgo PRNG algorithm
 * @param[in] prngContext Pointer to the PRNG context
 * @return Error code
 **/

error_t dhGenerateKeyPair(DhParameters *params, const PrngAlgo *prngAlgo, void *prngContext)
{
   error_t error;
   uint_t k;

   //Debug message
   TRACE_DEBUG("Generating Diffie-Hellman public value...\r\n");

   //Get the length in bits of the prime p
   k = mpiGetBitLength(&params->p);
   //Ensure the length is valid
   if(!k) return ERROR_INVALID_PARAMETER;

   //The private value shall be randomly generated
   error = mpiRand(&params->xa, k, prngAlgo, prngContext);
   //Any error to report?
   if(error) return error;

   //The private value shall be less than p
   if(mpiComp(&params->xa, &params->p) >= 0)
   {
      //Shift value to the right
      error = mpiShiftRight(&params->xa, 1);
      //Any error to report?
      if(error) return error;
   }

   //Debug message
   TRACE_DEBUG("  Private value:\r\n");
   TRACE_DEBUG_MPI("    ", &params->xa);

   //Calculate the corresponding public value (ya = g ^ xa mod p)
   error = mpiExpMod(&params->ya, &params->g, &params->xa, &params->p);
   //Any error to report?
   if(error) return error;

   //Debug message
   TRACE_DEBUG("  Public value:\r\n");
   TRACE_DEBUG_MPI("    ", &params->ya);

   //Check public value
   error = dhCheckPublicKey(&params->ya, &params->p);
   //Weak public value?
   if(error) return error;

   //Public value successfully generated
   return NO_ERROR;
}


/**
 * @brief Check Diffie-Hellman public value
 * @param[in] publicKey Public value to check
 * @param[in] p Prime modulus
 * @return Error code
 **/

error_t dhCheckPublicKey(const Mpi *publicKey, const Mpi *p)
{
   error_t error;
   Mpi a;

   //Initialize multiple precision integer
   mpiInit(&a);
   //Precompute p - 1
   error = mpiSubInt(&a, p, 1);

   //Check status
   if(!error)
   {
      //Reject weak public values 1 and p - 1
      if(mpiCompInt(publicKey, 1) <= 0)
         error = ERROR_ILLEGAL_PARAMETER;
      else if(mpiComp(publicKey, &a) >= 0)
         error = ERROR_ILLEGAL_PARAMETER;
   }

   //Free previously allocated resources
   mpiFree(&a);
   //Return status code
   return error;
}


/**
 * @brief Compute Diffie-Hellman shared secret
 * @param[in] params Pointer to the Diffie-Hellman parameters
 * @param[out] output Buffer where to store the shared secret
 * @param[in] outputSize Size of the buffer in bytes
 * @param[out] outputLength Length of the resulting shared secret
 * @return Error code
 **/

error_t dhComputeSharedSecret(DhParameters *params,
   uint8_t *output, size_t outputSize, size_t *outputLength)
{
   error_t error;
   size_t k;
   Mpi z;

   //Debug message
   TRACE_DEBUG("Computing Diffie-Hellman shared secret...\r\n");

   //Get the length in octets of the prime modulus
   k = mpiGetByteLength(&params->p);

   //Make sure that the output buffer is large enough
   if(outputSize < k)
      return ERROR_INVALID_LENGTH;

   //The multiple precision integer must be initialized before it can be used
   mpiInit(&z);

   //Start of exception handling block
   do
   {
      //Calculate the shared secret key (k = yb ^ xa mod p)
      error = mpiExpMod(&z, &params->yb, &params->xa, &params->p);
      //Any error to report?
      if(error) return error;

      //Convert the resulting integer to an octet string
      error = mpiWriteRaw(&z, output, k);
      //Conversion failed?
      if(error) return error;

      //Length of the resulting shared secret
      *outputLength = k;

      //Debug message
      TRACE_DEBUG("  Shared secret key (%u bytes):\r\n", *outputLength);
      TRACE_DEBUG_ARRAY("    ", output, *outputLength);

      //End of exception handling block
   } while(0);

   //Release previously allocated resources
   mpiFree(&z);
   //Return status code
   return error;
}

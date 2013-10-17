/**
 * @file dh.h
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
 * @author Oryx Embedded (www.oryx-embedded.com)
 * @version 1.3.8
 **/

#ifndef _DH_H
#define _DH_H

//Dependencies
#include "crypto.h"
#include "mpi.h"


/**
 * @brief Diffie-Hellman parameters
 **/

typedef struct
{
   Mpi p;  ///<Prime modulus
   Mpi g;  ///<Generator
   Mpi xa; ///<Out private value
   Mpi ya; ///<Our public value
   Mpi yb; ///<Peer's public value
} DhParameters;


//Diffie-Hellman related functions
void dhInitParameters(DhParameters *params);
void dhFreeParameters(DhParameters *params);

error_t dhGenerateKeyPair(DhParameters *params, const PrngAlgo *prngAlgo, void *prngContext);

error_t dhCheckPublicKey(const Mpi *publicKey, const Mpi *p);

error_t dhComputeSharedSecret(DhParameters *params,
   uint8_t *output, size_t outputSize, size_t *outputLength);

#endif

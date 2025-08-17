// Copyright (c) 2014-2024, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <vector>
#include "serialization/keyvalue_serialization.h"
#include "cryptonote_basic/workshare.h"
#include "cryptonote_basic/blobdatatype.h"
#include "crypto/hash.h"

namespace cryptonote
{

// Workshare protocol command IDs (extending the base command pool)
#define WS_COMMANDS_POOL_BASE 3000

  /************************************************************************/
  /* Workshare broadcast notification                                     */
  /************************************************************************/
  struct NOTIFY_NEW_WORKSHARE
  {
    const static int ID = WS_COMMANDS_POOL_BASE + 1;

    struct request_t
    {
      blobdata workshare_blob;        // Serialized workshare data
      crypto::hash workshare_id;      // Hash of the workshare for deduplication
      uint64_t current_blockchain_height; // Current chain height when sent

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(workshare_blob)
        KV_SERIALIZE_VAL_POD_AS_BLOB(workshare_id)
        KV_SERIALIZE(current_blockchain_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
  };

  /************************************************************************/
  /* Workshare inventory request                                          */
  /************************************************************************/
  struct NOTIFY_REQUEST_WORKSHARE_INVENTORY
  {
    const static int ID = WS_COMMANDS_POOL_BASE + 2;

    struct request_t
    {
      crypto::hash parent_block_id;   // Request workshares for this parent block
      uint64_t max_count;             // Maximum number of workshares to return
      uint64_t current_blockchain_height; // Current chain height when requested

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_VAL_POD_AS_BLOB(parent_block_id)
        KV_SERIALIZE(max_count)
        KV_SERIALIZE(current_blockchain_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
  };

  /************************************************************************/
  /* Workshare inventory response                                         */
  /************************************************************************/
  struct NOTIFY_RESPONSE_WORKSHARE_INVENTORY
  {
    const static int ID = WS_COMMANDS_POOL_BASE + 3;

    struct request_t
    {
      std::vector<crypto::hash> workshare_ids; // List of available workshare IDs
      crypto::hash parent_block_id;            // Parent block these workshares reference
      uint64_t current_blockchain_height;      // Current chain height when responded

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(workshare_ids)
        KV_SERIALIZE_VAL_POD_AS_BLOB(parent_block_id)
        KV_SERIALIZE(current_blockchain_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
  };

  /************************************************************************/
  /* Workshare data request                                               */
  /************************************************************************/
  struct NOTIFY_REQUEST_WORKSHARE_DATA
  {
    const static int ID = WS_COMMANDS_POOL_BASE + 4;

    struct request_t
    {
      std::vector<crypto::hash> workshare_ids; // Specific workshares to fetch
      uint64_t current_blockchain_height;      // Current chain height when requested

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(workshare_ids)
        KV_SERIALIZE(current_blockchain_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
  };

  /************************************************************************/
  /* Workshare data response                                              */
  /************************************************************************/
  struct NOTIFY_RESPONSE_WORKSHARE_DATA
  {
    const static int ID = WS_COMMANDS_POOL_BASE + 5;

    struct workshare_entry
    {
      crypto::hash workshare_id;      // ID of the workshare
      blobdata workshare_blob;        // Serialized workshare data

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_VAL_POD_AS_BLOB(workshare_id)
        KV_SERIALIZE(workshare_blob)
      END_KV_SERIALIZE_MAP()
    };

    struct request_t
    {
      std::vector<workshare_entry> workshares; // Requested workshare data
      std::vector<crypto::hash> missed_ids;     // IDs that couldn't be found
      uint64_t current_blockchain_height;      // Current chain height when responded

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(workshares)
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(missed_ids)
        KV_SERIALIZE(current_blockchain_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
  };

  /************************************************************************/
  /* Workshare pool synchronization request                              */
  /************************************************************************/
  struct NOTIFY_REQUEST_WORKSHARE_POOL_SYNC
  {
    const static int ID = WS_COMMANDS_POOL_BASE + 6;

    struct request_t
    {
      std::vector<crypto::hash> known_workshares; // Workshares the requesting peer already has
      uint64_t current_blockchain_height;         // Current chain height when requested

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(known_workshares)
        KV_SERIALIZE(current_blockchain_height)
      END_KV_SERIALIZE_MAP()
    };
    typedef epee::misc_utils::struct_init<request_t> request;
  };

  /************************************************************************/
  /* Workshare rate limiting context                                     */
  /************************************************************************/
  struct workshare_rate_limit_context
  {
    uint64_t last_reset_time;        // Last time the rate limit counter was reset
    uint32_t workshares_received;    // Number of workshares received in current window
    uint32_t max_workshares_per_second; // Maximum allowed rate (default: 10)
    uint32_t rate_window_seconds;    // Rate limiting window size (default: 1 second)

    workshare_rate_limit_context():
      last_reset_time(0),
      workshares_received(0),
      max_workshares_per_second(10),
      rate_window_seconds(1)
    {}

    bool is_rate_limited(uint64_t current_time)
    {
      // Reset counter if window has passed
      if (current_time >= last_reset_time + rate_window_seconds)
      {
        last_reset_time = current_time;
        workshares_received = 0;
      }
      
      return workshares_received >= max_workshares_per_second;
    }

    void record_workshare(uint64_t current_time)
    {
      // Reset counter if window has passed
      if (current_time >= last_reset_time + rate_window_seconds)
      {
        last_reset_time = current_time;
        workshares_received = 0;
      }
      
      workshares_received++;
    }
  };
}
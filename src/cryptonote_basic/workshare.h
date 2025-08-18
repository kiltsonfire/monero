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

#include <atomic>
#include "crypto/hash.h"
#include "serialization/serialization.h"
#include "serialization/keyvalue_serialization.h"
#include "serialization/difficulty_type.h"
#include "difficulty.h"
#include "cryptonote_config.h"

namespace cryptonote
{
  /**
   * @brief Workshare structure - identical to block_header
   * 
   * Workshares are exactly block headers that meet a reduced difficulty threshold
   * (~7 bits easier than full block difficulty). They provide visibility into
   * mining activity and contribute to network security measurement.
   * 
   * Since workshares are identical to block headers, they can be produced
   * directly from mining operations without any additional fields.
   */
  struct workshare
  {
    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    crypto::hash prev_id;  // Previous block hash
    uint32_t nonce;
    uint32_t workshare_count;  // Number of workshares (matches block_header)
    
    // Validation cache (not serialized)
    mutable std::atomic<bool> hash_valid;
    mutable crypto::hash hash;
    
    workshare(): 
      major_version(0),
      minor_version(0), 
      timestamp(0),
      prev_id(crypto::null_hash),
      nonce(0),
      workshare_count(0),
      hash_valid(false),
      hash(crypto::null_hash)
    {}
    
    workshare(const workshare& other):
      major_version(other.major_version),
      minor_version(other.minor_version),
      timestamp(other.timestamp),
      prev_id(other.prev_id),
      nonce(other.nonce),
      workshare_count(other.workshare_count),
      hash_valid(other.is_hash_valid()),
      hash(other.hash)
    {}
    
    workshare& operator=(const workshare& other)
    {
      if (this != &other)
      {
        major_version = other.major_version;
        minor_version = other.minor_version;
        timestamp = other.timestamp;
        prev_id = other.prev_id;
        nonce = other.nonce;
        workshare_count = other.workshare_count;
        set_hash_valid(other.is_hash_valid());
        hash = other.hash;
      }
      return *this;
    }
    
    void set_null()
    {
      major_version = 0;
      minor_version = 0;
      timestamp = 0;
      prev_id = crypto::null_hash;
      nonce = 0;
      workshare_count = 0;
      invalidate_hashes();
    }
    
    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(prev_id)
      FIELD(nonce)
      VARINT_FIELD(workshare_count)
    END_SERIALIZE()
    
    bool is_hash_valid() const { return hash_valid.load(std::memory_order_acquire); }
    void set_hash_valid(bool v) const { hash_valid.store(v, std::memory_order_release); }
    void set_hash(const crypto::hash &h) const { hash = h; set_hash_valid(true); }
    void invalidate_hashes() { set_hash_valid(false); }
  };

  /**
   * @brief Workshare verification context for validation results
   * 
   * Contains detailed information about workshare validation failures
   * to enable proper error handling and debugging.
   */
  struct workshare_verification_context
  {
    bool m_verification_failed;     // General validation failure
    bool m_low_difficulty;          // Hash doesn't meet required difficulty
    bool m_unknown_block;           // Previous block not found
    bool m_invalid_version;         // Invalid version
    bool m_invalid_timestamp;       // Timestamp outside acceptable range
    bool m_already_exists;          // Workshare already in pool
    bool m_pool_full;               // Workshare pool at capacity
    
    workshare_verification_context():
      m_verification_failed(false),
      m_low_difficulty(false),
      m_unknown_block(false),
      m_invalid_version(false),
      m_invalid_timestamp(false),
      m_already_exists(false),
      m_pool_full(false)
    {}
  };

  /**
   * @brief Workshare pool entry for memory pool storage
   * 
   * Wrapper around workshare with additional metadata needed
   * for pool management, indexing, and expiry.
   */
  struct workshare_pool_entry
  {
    workshare ws;                   // The workshare data (identical to block_header)
    crypto::hash id;               // Hash of workshare
    uint64_t receive_time;         // Unix timestamp when received
    uint64_t block_height;         // Height of the block this workshare references
    bool kept_by_block;            // True if included in a block
    
    workshare_pool_entry():
      ws(),
      id(crypto::null_hash),
      receive_time(0),
      block_height(0),
      kept_by_block(false)
    {}
    
    workshare_pool_entry(const workshare& _ws, const crypto::hash& _id, uint64_t _receive_time, uint64_t _block_height):
      ws(_ws),
      id(_id),
      receive_time(_receive_time),
      block_height(_block_height),
      kept_by_block(false)
    {}
    
    BEGIN_SERIALIZE()
      FIELD(ws)
      FIELD(id)
      VARINT_FIELD(receive_time)
      VARINT_FIELD(block_height)
      FIELD(kept_by_block)
    END_SERIALIZE()
  };
}
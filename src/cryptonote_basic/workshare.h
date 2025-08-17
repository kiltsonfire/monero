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
#include "difficulty.h"
#include "cryptonote_config.h"

namespace cryptonote
{
  /**
   * @brief Workshare structure containing partial proof-of-work solutions
   * 
   * Workshares represent mining work that meets a reduced difficulty threshold
   * (~7 bits easier than full block difficulty). They provide visibility into
   * mining activity and contribute to network security measurement.
   * 
   * CRITICAL SECURITY PROPERTY: Workshares can only be included in blocks if
   * they reference the parent block of the including block. This prevents
   * share hoarding attacks.
   */
  struct workshare
  {
    // Block header compatibility fields
    uint8_t major_version;           // Version compatibility with referenced block
    uint8_t minor_version;           // Version compatibility with referenced block
    uint64_t timestamp;              // Unix timestamp when workshare was created
    crypto::hash parent_block_id;    // CRITICAL: Must reference parent of including block
    crypto::hash referenced_block_id; // The block this workshare was mining for
    uint32_t nonce;                  // Mining nonce that produced this workshare
    
    // Workshare-specific fields
    crypto::hash miner_address_hash; // Hash of mining address for attribution
    difficulty_type workshare_difficulty; // The difficulty this workshare meets
    
    // Validation cache
    mutable std::atomic<bool> hash_valid;
    mutable crypto::hash hash;
    
    workshare(): 
      major_version(0),
      minor_version(0), 
      timestamp(0),
      parent_block_id(crypto::null_hash),
      referenced_block_id(crypto::null_hash),
      nonce(0),
      miner_address_hash(crypto::null_hash),
      workshare_difficulty(0),
      hash_valid(false),
      hash(crypto::null_hash)
    {}
    
    workshare(const workshare& other):
      major_version(other.major_version),
      minor_version(other.minor_version),
      timestamp(other.timestamp),
      parent_block_id(other.parent_block_id),
      referenced_block_id(other.referenced_block_id),
      nonce(other.nonce),
      miner_address_hash(other.miner_address_hash),
      workshare_difficulty(other.workshare_difficulty),
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
        parent_block_id = other.parent_block_id;
        referenced_block_id = other.referenced_block_id;
        nonce = other.nonce;
        miner_address_hash = other.miner_address_hash;
        workshare_difficulty = other.workshare_difficulty;
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
      parent_block_id = crypto::null_hash;
      referenced_block_id = crypto::null_hash;
      nonce = 0;
      miner_address_hash = crypto::null_hash;
      workshare_difficulty = 0;
      invalidate_hashes();
    }
    
    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(parent_block_id)
      FIELD(referenced_block_id)
      FIELD(nonce)
      FIELD(miner_address_hash)
      VARINT_FIELD(workshare_difficulty)
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
    bool m_unknown_block;           // Referenced block not found
    bool m_unknown_parent;          // Parent block not found
    bool m_invalid_version;         // Version mismatch with referenced block
    bool m_invalid_timestamp;       // Timestamp outside acceptable range
    bool m_invalid_difficulty;      // Incorrect difficulty calculation
    bool m_invalid_parent_reference; // Parent reference validation failed
    bool m_already_exists;          // Workshare already in pool
    bool m_pool_full;               // Workshare pool at capacity
    
    workshare_verification_context():
      m_verification_failed(false),
      m_low_difficulty(false),
      m_unknown_block(false),
      m_unknown_parent(false),
      m_invalid_version(false),
      m_invalid_timestamp(false),
      m_invalid_difficulty(false),
      m_invalid_parent_reference(false),
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
    workshare ws;                   // The workshare data
    crypto::hash id;               // SHA3-256 hash of workshare
    uint64_t receive_time;         // Unix timestamp when received
    uint64_t referenced_height;    // Height of referenced block
    bool kept_by_block;            // True if included in a block
    
    workshare_pool_entry():
      ws(),
      id(crypto::null_hash),
      receive_time(0),
      referenced_height(0),
      kept_by_block(false)
    {}
    
    workshare_pool_entry(const workshare& _ws, const crypto::hash& _id, uint64_t _receive_time, uint64_t _referenced_height):
      ws(_ws),
      id(_id),
      receive_time(_receive_time),
      referenced_height(_referenced_height),
      kept_by_block(false)
    {}
    
    BEGIN_SERIALIZE()
      FIELD(ws)
      FIELD(id)
      VARINT_FIELD(receive_time)
      VARINT_FIELD(referenced_height)
      FIELD(kept_by_block)
    END_SERIALIZE()
  };
}
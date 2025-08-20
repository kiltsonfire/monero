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

#include "workshare_pool.h"
#include "blockchain.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "misc_language.h"
#include "time_helper.h"
#include <boost/uuid/uuid_io.hpp>
#include <unordered_set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "workshare_pool"

namespace cryptonote
{
  //------------------------------------------------------------------
  workshare_memory_pool::workshare_memory_pool(Blockchain& blockchain)
    : m_blockchain(blockchain)
    , m_write_pos(0)
    , m_total_workshares(0)
  {
    MINFO("Workshare memory pool initialized with lock-free ring buffer (size: " << POOL_SIZE << ")");
  }

  //------------------------------------------------------------------
  bool workshare_memory_pool::add_workshare(const workshare& ws, const crypto::hash& id, 
                                            const boost::uuids::uuid& peer_id, 
                                            workshare_verification_context& tvc)
  {
    MDEBUG("[add_workshare] Starting - id: " << id << ", peer_id: " << peer_id);
    
    // First check if it already exists (lock-free scan)
    for (size_t i = 0; i < POOL_SIZE; ++i)
    {
      if (m_ring_buffer[i].valid.load(std::memory_order_acquire))
      {
        if (m_ring_buffer[i].entry.id == id)
        {
          MDEBUG("Workshare " << id << " already exists in pool");
          tvc.m_already_exists = true;
          return false;
        }
      }
    }
    
    // Validate the workshare
    if (!validate_workshare(ws, id, tvc))
    {
      LOG_PRINT_L2("Workshare " << id << " validation failed");
      return false;
    }
    
    // Get the next position in the ring buffer (lock-free)
    uint64_t pos = m_write_pos.fetch_add(1, std::memory_order_relaxed) % POOL_SIZE;
    
    // Mark the entry as invalid while we're writing
    m_ring_buffer[pos].valid.store(false, std::memory_order_release);
    
    // Write the new entry
    const uint64_t current_time = static_cast<uint64_t>(std::time(nullptr));
    m_ring_buffer[pos].entry = workshare_pool_entry(ws, id, current_time);
    
    // Mark the entry as valid (memory fence ensures entry is fully written)
    m_ring_buffer[pos].valid.store(true, std::memory_order_release);
    
    // Update statistics
    m_total_workshares.fetch_add(1, std::memory_order_relaxed);
    
    LOG_PRINT_L1("Added workshare " << id << " to pool at position " << pos << " (prev_id: " << ws.prev_id << ")");
    
    return true;
  }

  //------------------------------------------------------------------
  std::vector<workshare_pool_entry> workshare_memory_pool::get_workshares_for_parent(
      const crypto::hash& parent_block_id, size_t max_count)
  {
    std::vector<workshare_pool_entry> result;
    result.reserve(std::min(max_count, (size_t)300));
    
    // Lock-free scan through the ring buffer
    for (size_t i = 0; i < POOL_SIZE && result.size() < max_count; ++i)
    {
      if (m_ring_buffer[i].valid.load(std::memory_order_acquire))
      {
        const auto& entry = m_ring_buffer[i].entry;
        if (entry.ws.prev_id == parent_block_id)
        {
          result.push_back(entry);
        }
      }
    }
    
    return result;
  }

  //------------------------------------------------------------------
  std::vector<workshare_pool_entry> workshare_memory_pool::get_all_workshares()
  {
    std::vector<workshare_pool_entry> result;
    result.reserve(POOL_SIZE);
    
    // Lock-free scan through the ring buffer
    for (size_t i = 0; i < POOL_SIZE; ++i)
    {
      if (m_ring_buffer[i].valid.load(std::memory_order_acquire))
      {
        result.push_back(m_ring_buffer[i].entry);
      }
    }
    
    return result;
  }

  //------------------------------------------------------------------
  bool workshare_memory_pool::get_workshare(const crypto::hash& id, workshare_pool_entry& entry)
  {
    // Lock-free search through the ring buffer
    for (size_t i = 0; i < POOL_SIZE; ++i)
    {
      if (m_ring_buffer[i].valid.load(std::memory_order_acquire))
      {
        if (m_ring_buffer[i].entry.id == id)
        {
          entry = m_ring_buffer[i].entry;
          return true;
        }
      }
    }
    
    return false;
  }

  //------------------------------------------------------------------
  void workshare_memory_pool::get_pool_stats(size_t& total_workshares, size_t& active_parents)
  {
    total_workshares = 0;
    std::unordered_set<crypto::hash> parent_blocks;
    
    // Lock-free scan through the ring buffer
    for (size_t i = 0; i < POOL_SIZE; ++i)
    {
      if (m_ring_buffer[i].valid.load(std::memory_order_acquire))
      {
        total_workshares++;
        parent_blocks.insert(m_ring_buffer[i].entry.ws.prev_id);
      }
    }
    
    active_parents = parent_blocks.size();
  }

  //------------------------------------------------------------------
  bool workshare_memory_pool::has_workshare(const crypto::hash& id)
  {
    // Lock-free search through the ring buffer
    for (size_t i = 0; i < POOL_SIZE; ++i)
    {
      if (m_ring_buffer[i].valid.load(std::memory_order_acquire))
      {
        if (m_ring_buffer[i].entry.id == id)
        {
          return true;
        }
      }
    }
    
    return false;
  }

  //------------------------------------------------------------------
  std::vector<crypto::hash> workshare_memory_pool::get_workshare_inventory(
      const crypto::hash& parent_block_id, size_t max_count)
  {
    std::vector<crypto::hash> result;
    result.reserve(std::min(max_count, (size_t)300));
    
    // Lock-free scan through the ring buffer
    for (size_t i = 0; i < POOL_SIZE && result.size() < max_count; ++i)
    {
      if (m_ring_buffer[i].valid.load(std::memory_order_acquire))
      {
        const auto& entry = m_ring_buffer[i].entry;
        if (entry.ws.prev_id == parent_block_id)
        {
          result.push_back(entry.id);
        }
      }
    }
    
    return result;
  }

  //------------------------------------------------------------------
  bool workshare_memory_pool::validate_workshare(const workshare& ws, const crypto::hash& id, 
                                                 workshare_verification_context& tvc)
  {
    // Check if previous block exists (the block this workshare references)
    if (!m_blockchain.have_block(ws.prev_id))
    {
      LOG_PRINT_L2("Workshare " << id << " references unknown block " << ws.prev_id);
      tvc.m_unknown_block = true;
      return false;
    }
    
    // Validate timestamp (within reasonable bounds)
    const uint64_t current_time = static_cast<uint64_t>(std::time(nullptr));
    const uint64_t max_timestamp_drift = 600; // 10 minutes
    
    if (ws.timestamp > current_time + max_timestamp_drift)
    {
      LOG_PRINT_L2("Workshare " << id << " has timestamp too far in future: " << ws.timestamp 
                   << " vs current " << current_time);
      tvc.m_invalid_timestamp = true;
      return false;
    }
    
    // TODO: Validate proof of work hash meets workshare difficulty threshold
    // The actual PoW validation should check that the workshare hash meets
    // the required difficulty (block_difficulty >> 7)
    
    return true;
  }
}
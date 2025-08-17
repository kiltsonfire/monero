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

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "workshare_pool"

namespace cryptonote
{
  //------------------------------------------------------------------
  workshare_memory_pool::workshare_memory_pool(Blockchain& blockchain)
    : m_blockchain(blockchain)
    , m_total_workshares(0)
    , m_last_cleanup_time(0)
  {
    MINFO("Workshare memory pool initialized");
  }

  //------------------------------------------------------------------
  bool workshare_memory_pool::add_workshare(const workshare& ws, const crypto::hash& id, 
                                            const boost::uuids::uuid& peer_id, 
                                            workshare_verification_context& tvc)
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    const uint64_t current_time = static_cast<uint64_t>(std::time(nullptr));
    
    // Check rate limiting
    if (is_rate_limited(peer_id))
    {
      LOG_PRINT_L2("Workshare " << id << " rejected due to rate limiting from peer " << peer_id);
      tvc.m_pool_full = true;
      return false;
    }
    
    // Check if already exists
    if (m_workshares.find(id) != m_workshares.end())
    {
      LOG_PRINT_L2("Workshare " << id << " already exists in pool");
      tvc.m_already_exists = true;
      return false;
    }
    
    // Validate the workshare
    if (!validate_workshare(ws, id, tvc))
    {
      LOG_PRINT_L2("Workshare " << id << " validation failed");
      return false;
    }
    
    // Check parent block capacity
    auto parent_it = m_workshares_by_parent.find(ws.parent_block_id);
    if (parent_it != m_workshares_by_parent.end() && 
        parent_it->second.size() >= MAX_WORKSHARES_PER_PARENT)
    {
      LOG_PRINT_L2("Parent block " << ws.parent_block_id << " has reached maximum workshare capacity (" 
                   << MAX_WORKSHARES_PER_PARENT << ")");
      tvc.m_pool_full = true;
      return false;
    }
    
    // Get referenced block height for the entry
    uint64_t referenced_height = 0;
    if (!m_blockchain.get_block_height(ws.referenced_block_id, referenced_height))
    {
      LOG_PRINT_L2("Workshare " << id << " references unknown block " << ws.referenced_block_id);
      tvc.m_unknown_block = true;
      return false;
    }
    
    // Create pool entry
    workshare_pool_entry entry(ws, id, current_time, referenced_height);
    
    // Add to main storage
    m_workshares[id] = entry;
    
    // Add to parent index
    m_workshares_by_parent[ws.parent_block_id].insert(id);
    
    // Record rate limiting
    record_peer_workshare(peer_id);
    
    // Update statistics
    m_total_workshares++;
    
    LOG_PRINT_L1("Added workshare " << id << " to pool (parent: " << ws.parent_block_id << 
                 ", referenced: " << ws.referenced_block_id << ", height: " << referenced_height << ")");
    
    return true;
  }

  //------------------------------------------------------------------
  std::vector<workshare_pool_entry> workshare_memory_pool::get_workshares_for_parent(
      const crypto::hash& parent_block_id, size_t max_count)
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    std::vector<workshare_pool_entry> result;
    
    auto it = m_workshares_by_parent.find(parent_block_id);
    if (it == m_workshares_by_parent.end())
      return result;
    
    result.reserve(std::min(it->second.size(), max_count));
    
    size_t count = 0;
    for (const auto& ws_id : it->second)
    {
      if (count >= max_count)
        break;
        
      auto ws_it = m_workshares.find(ws_id);
      if (ws_it != m_workshares.end())
      {
        result.push_back(ws_it->second);
        count++;
      }
    }
    
    return result;
  }

  //------------------------------------------------------------------
  std::vector<workshare_pool_entry> workshare_memory_pool::get_all_workshares()
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    std::vector<workshare_pool_entry> result;
    result.reserve(m_workshares.size());
    
    for (const auto& pair : m_workshares)
    {
      result.push_back(pair.second);
    }
    
    return result;
  }

  //------------------------------------------------------------------
  bool workshare_memory_pool::get_workshare(const crypto::hash& id, workshare_pool_entry& entry)
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    auto it = m_workshares.find(id);
    if (it == m_workshares.end())
      return false;
      
    entry = it->second;
    return true;
  }

  //------------------------------------------------------------------
  void workshare_memory_pool::remove_workshares(const std::vector<crypto::hash>& workshare_ids)
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    for (const auto& id : workshare_ids)
    {
      auto it = m_workshares.find(id);
      if (it != m_workshares.end())
      {
        const crypto::hash& parent_id = it->second.ws.parent_block_id;
        
        // Remove from parent index
        auto parent_it = m_workshares_by_parent.find(parent_id);
        if (parent_it != m_workshares_by_parent.end())
        {
          parent_it->second.erase(id);
          if (parent_it->second.empty())
          {
            m_workshares_by_parent.erase(parent_it);
          }
        }
        
        // Remove from main storage
        m_workshares.erase(it);
        m_total_workshares--;
        
        LOG_PRINT_L2("Removed workshare " << id << " from pool");
      }
    }
  }

  //------------------------------------------------------------------
  void workshare_memory_pool::mark_workshares_kept_by_block(
      const std::vector<crypto::hash>& workshare_ids, bool kept)
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    for (const auto& id : workshare_ids)
    {
      auto it = m_workshares.find(id);
      if (it != m_workshares.end())
      {
        it->second.kept_by_block = kept;
        LOG_PRINT_L3("Marked workshare " << id << " as " << (kept ? "kept" : "not kept") << " by block");
      }
    }
  }

  //------------------------------------------------------------------
  void workshare_memory_pool::cleanup_expired()
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    const uint64_t current_time = static_cast<uint64_t>(std::time(nullptr));
    
    // Clean up expired workshares
    std::vector<crypto::hash> expired_workshares;
    
    for (const auto& pair : m_workshares)
    {
      const auto& entry = pair.second;
      if (current_time > entry.receive_time + WORKSHARE_EXPIRY_TIME)
      {
        expired_workshares.push_back(pair.first);
      }
    }
    
    if (!expired_workshares.empty())
    {
      LOG_PRINT_L1("Removing " << expired_workshares.size() << " expired workshares");
      remove_workshares(expired_workshares);
    }
    
    // Clean up rate limiting data every 10 minutes
    if (current_time > m_last_cleanup_time + 600)
    {
      cleanup_rate_limits();
      m_last_cleanup_time = current_time;
    }
  }

  //------------------------------------------------------------------
  void workshare_memory_pool::get_pool_stats(size_t& total_workshares, size_t& active_parents)
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    total_workshares = m_workshares.size();
    active_parents = m_workshares_by_parent.size();
  }

  //------------------------------------------------------------------
  bool workshare_memory_pool::has_workshare(const crypto::hash& id)
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    return m_workshares.find(id) != m_workshares.end();
  }

  //------------------------------------------------------------------
  std::vector<crypto::hash> workshare_memory_pool::get_workshare_inventory(
      const crypto::hash& parent_block_id, size_t max_count)
  {
    CRITICAL_REGION_LOCAL(m_pool_lock);
    
    std::vector<crypto::hash> result;
    
    auto it = m_workshares_by_parent.find(parent_block_id);
    if (it == m_workshares_by_parent.end())
      return result;
    
    result.reserve(std::min(it->second.size(), max_count));
    
    size_t count = 0;
    for (const auto& ws_id : it->second)
    {
      if (count >= max_count)
        break;
      result.push_back(ws_id);
      count++;
    }
    
    return result;
  }

  //------------------------------------------------------------------
  bool workshare_memory_pool::validate_workshare(const workshare& ws, const crypto::hash& id, 
                                                 workshare_verification_context& tvc)
  {
    // Check if parent block exists
    if (!m_blockchain.have_block(ws.parent_block_id))
    {
      LOG_PRINT_L2("Workshare " << id << " references unknown parent block " << ws.parent_block_id);
      tvc.m_unknown_parent = true;
      return false;
    }
    
    // Check if referenced block exists
    if (!m_blockchain.have_block(ws.referenced_block_id))
    {
      LOG_PRINT_L2("Workshare " << id << " references unknown block " << ws.referenced_block_id);
      tvc.m_unknown_block = true;
      return false;
    }
    
    // Validate parent reference constraint
    uint64_t parent_height = 0;
    uint64_t referenced_height = 0;
    
    if (!m_blockchain.get_block_height(ws.parent_block_id, parent_height) ||
        !m_blockchain.get_block_height(ws.referenced_block_id, referenced_height))
    {
      LOG_PRINT_L2("Workshare " << id << " unable to get block heights for validation");
      tvc.m_verification_failed = true;
      return false;
    }
    
    // Parent must be exactly one block ahead of referenced block
    if (parent_height != referenced_height + 1)
    {
      LOG_PRINT_L2("Workshare " << id << " invalid parent reference: parent height " << parent_height 
                   << " should be " << (referenced_height + 1));
      tvc.m_invalid_parent_reference = true;
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
    
    // Validate workshare difficulty meets minimum threshold
    difficulty_type min_difficulty = m_blockchain.get_difficulty_for_next_block();
    difficulty_type workshare_threshold = min_difficulty >> 7; // ~7 bits easier
    
    if (ws.workshare_difficulty < workshare_threshold)
    {
      LOG_PRINT_L2("Workshare " << id << " difficulty " << ws.workshare_difficulty 
                   << " below threshold " << workshare_threshold);
      tvc.m_low_difficulty = true;
      return false;
    }
    
    // TODO: Validate proof of work hash when mining utilities are available
    // For now, we trust the difficulty value provided
    
    return true;
  }

  //------------------------------------------------------------------
  bool workshare_memory_pool::is_rate_limited(const boost::uuids::uuid& peer_id)
  {
    const uint64_t current_time = static_cast<uint64_t>(std::time(nullptr));
    
    auto it = m_peer_rate_limits.find(peer_id);
    if (it == m_peer_rate_limits.end())
      return false; // First workshare from this peer
      
    return it->second.is_rate_limited(current_time);
  }

  //------------------------------------------------------------------
  void workshare_memory_pool::record_peer_workshare(const boost::uuids::uuid& peer_id)
  {
    const uint64_t current_time = static_cast<uint64_t>(std::time(nullptr));
    
    auto& context = m_peer_rate_limits[peer_id];
    context.record_workshare(current_time);
  }

  //------------------------------------------------------------------
  void workshare_memory_pool::cleanup_rate_limits()
  {
    const uint64_t current_time = static_cast<uint64_t>(std::time(nullptr));
    const uint64_t cleanup_threshold = 3600; // Remove peer data after 1 hour of inactivity
    
    auto it = m_peer_rate_limits.begin();
    while (it != m_peer_rate_limits.end())
    {
      if (current_time > it->second.last_reset_time + cleanup_threshold)
      {
        it = m_peer_rate_limits.erase(it);
      }
      else
      {
        ++it;
      }
    }
  }
}
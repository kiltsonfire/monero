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
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <chrono>

#include "crypto/hash.h"
#include "cryptonote_basic/workshare.h"
#include "cryptonote_basic/verification_context.h"
#include "include_base_utils.h"
#include "string_tools.h"
#include "syncobj.h"

namespace cryptonote
{
  class Blockchain;

  /**
   * @brief Memory pool for workshares with rate limiting and expiry
   * 
   * Manages workshares received from the network before they are included in blocks.
   * Provides rate limiting per peer, automatic expiry, and efficient lookup.
   * 
   * Key features:
   * - Maximum 300 workshares per parent block
   * - 1 hour expiry time for unused workshares
   * - Rate limiting: 10 workshares/second per peer
   * - Thread-safe operations
   * - Efficient parent block indexing
   */
  class workshare_memory_pool: boost::noncopyable
  {
  public:
    /**
     * @brief Constructor
     * @param blockchain Reference to the blockchain for validation
     */
    workshare_memory_pool(Blockchain& blockchain);

    /**
     * @brief Add a workshare to the memory pool
     * @param ws The workshare to add
     * @param id Pre-computed hash of the workshare
     * @param peer_id ID of the peer that sent this workshare
     * @param tvc Verification context for validation results
     * @return true if successfully added, false otherwise
     */
    bool add_workshare(const workshare& ws, const crypto::hash& id, 
                      const boost::uuids::uuid& peer_id, workshare_verification_context& tvc);

    /**
     * @brief Get workshares for a specific parent block
     * @param parent_block_id The parent block hash
     * @param max_count Maximum number of workshares to return
     * @return Vector of workshare pool entries
     */
    std::vector<workshare_pool_entry> get_workshares_for_parent(
        const crypto::hash& parent_block_id, size_t max_count = 300);

    /**
     * @brief Get all workshares in the pool
     * @return Vector of all workshare pool entries
     */
    std::vector<workshare_pool_entry> get_all_workshares();

    /**
     * @brief Get workshare by ID
     * @param id The workshare hash
     * @param entry Output parameter for the workshare entry
     * @return true if found, false otherwise
     */
    bool get_workshare(const crypto::hash& id, workshare_pool_entry& entry);

    /**
     * @brief Remove workshares that have been included in a block
     * @param workshare_ids Vector of workshare IDs to remove
     */
    void remove_workshares(const std::vector<crypto::hash>& workshare_ids);

    /**
     * @brief Mark workshares as kept by block (for reorganizations)
     * @param workshare_ids Vector of workshare IDs to mark
     * @param kept True to mark as kept, false to unmark
     */
    void mark_workshares_kept_by_block(const std::vector<crypto::hash>& workshare_ids, bool kept);

    /**
     * @brief Clean up expired workshares and reset rate limits
     * Called periodically by the daemon
     */
    void cleanup_expired();

    /**
     * @brief Get current pool statistics
     * @param total_workshares Output for total workshare count
     * @param active_parents Output for number of parent blocks with workshares
     */
    void get_pool_stats(size_t& total_workshares, size_t& active_parents);

    /**
     * @brief Check if workshare already exists in pool
     * @param id The workshare hash
     * @return true if exists, false otherwise
     */
    bool has_workshare(const crypto::hash& id);

    /**
     * @brief Get workshare IDs for inventory requests
     * @param parent_block_id The parent block to query
     * @param max_count Maximum number of IDs to return
     * @return Vector of workshare IDs
     */
    std::vector<crypto::hash> get_workshare_inventory(
        const crypto::hash& parent_block_id, size_t max_count = 300);

  private:
    /**
     * @brief Validate a workshare before adding to pool
     * @param ws The workshare to validate
     * @param id The workshare hash
     * @param tvc Verification context for results
     * @return true if valid, false otherwise
     */
    bool validate_workshare(const workshare& ws, const crypto::hash& id, 
                           workshare_verification_context& tvc);

    /**
     * @brief Check rate limiting for a peer
     * @param peer_id The peer ID
     * @return true if rate limited, false if allowed
     */
    bool is_rate_limited(const boost::uuids::uuid& peer_id);

    /**
     * @brief Record a workshare reception for rate limiting
     * @param peer_id The peer ID
     */
    void record_peer_workshare(const boost::uuids::uuid& peer_id);

    /**
     * @brief Clean up rate limiting data for inactive peers
     */
    void cleanup_rate_limits();

  private:
    // Core pool data
    std::unordered_map<crypto::hash, workshare_pool_entry> m_workshares; // hash -> entry
    std::unordered_map<crypto::hash, std::unordered_set<crypto::hash>> m_workshares_by_parent; // parent -> set of worksheet hashes
    
    // Rate limiting per peer
    struct peer_rate_context
    {
      uint64_t last_reset_time;
      uint32_t workshares_received;
      static constexpr uint32_t MAX_WORKSHARES_PER_SECOND = 10;
      static constexpr uint32_t RATE_WINDOW_SECONDS = 1;
      
      peer_rate_context() : last_reset_time(0), workshares_received(0) {}
      
      bool is_rate_limited(uint64_t current_time)
      {
        if (current_time >= last_reset_time + RATE_WINDOW_SECONDS)
        {
          last_reset_time = current_time;
          workshares_received = 0;
        }
        return workshares_received >= MAX_WORKSHARES_PER_SECOND;
      }
      
      void record_workshare(uint64_t current_time)
      {
        if (current_time >= last_reset_time + RATE_WINDOW_SECONDS)
        {
          last_reset_time = current_time;
          workshares_received = 0;
        }
        workshares_received++;
      }
    };
    
    std::map<boost::uuids::uuid, peer_rate_context> m_peer_rate_limits;
    
    // Thread synchronization
    mutable epee::critical_section m_pool_lock;
    
    // Pool configuration
    static constexpr size_t MAX_WORKSHARES_PER_PARENT = 300;
    static constexpr uint64_t WORKSHARE_EXPIRY_TIME = 1200; // 20 minutes in seconds
    
    // References
    Blockchain& m_blockchain;
    
    // Statistics
    std::atomic<size_t> m_total_workshares;
    uint64_t m_last_cleanup_time;
  };
}
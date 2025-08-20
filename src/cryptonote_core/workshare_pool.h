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

#include <array>
#include <atomic>
#include <vector>
#include <chrono>

#include "crypto/hash.h"
#include "cryptonote_basic/workshare.h"
#include "cryptonote_basic/verification_context.h"
#include "include_base_utils.h"
#include "string_tools.h"

namespace cryptonote
{
  class Blockchain;

  /**
   * @brief Lock-free memory pool for workshares using a ring buffer
   * 
   * Manages workshares using a fixed-size ring buffer with lock-free operations.
   * Old entries are automatically overwritten when the buffer fills up.
   * 
   * Key features:
   * - Lock-free ring buffer implementation (10,000 entries)
   * - No explicit expiry - old entries naturally get overwritten
   * - Wait-free reads
   * - Maximum 300 workshares per parent block for inclusion
   * - No memory allocation after initialization
   */
  class workshare_memory_pool: boost::noncopyable
  {
  public:
    // Fixed size of the ring buffer
    static constexpr size_t POOL_SIZE = 10000;
    static constexpr size_t MAX_WORKSHARES_PER_PARENT = 300;

    /**
     * @brief Constructor
     * @param blockchain Reference to the blockchain for validation
     */
    workshare_memory_pool(Blockchain& blockchain);

    /**
     * @brief Add a workshare to the ring buffer (lock-free)
     * @param ws The workshare to add
     * @param id Pre-computed hash of the workshare
     * @param peer_id ID of the peer that sent this workshare (unused in lock-free design)
     * @param tvc Verification context for validation results
     * @return true if successfully added, false otherwise
     */
    bool add_workshare(const workshare& ws, const crypto::hash& id, 
                      const boost::uuids::uuid& peer_id, workshare_verification_context& tvc);

    /**
     * @brief Get workshares for a specific parent block (lock-free read)
     * @param parent_block_id The parent block hash
     * @param max_count Maximum number of workshares to return
     * @return Vector of workshare pool entries
     */
    std::vector<workshare_pool_entry> get_workshares_for_parent(
        const crypto::hash& parent_block_id, size_t max_count = MAX_WORKSHARES_PER_PARENT);

    /**
     * @brief Get all valid workshares in the pool (lock-free read)
     * @return Vector of all workshare pool entries
     */
    std::vector<workshare_pool_entry> get_all_workshares();

    /**
     * @brief Get workshare by ID (lock-free read)
     * @param id The workshare hash
     * @param entry Output parameter for the workshare entry
     * @return true if found, false otherwise
     */
    bool get_workshare(const crypto::hash& id, workshare_pool_entry& entry);

    /**
     * @brief No-op in ring buffer design (old entries get overwritten)
     */
    void remove_workshares(const std::vector<crypto::hash>& workshare_ids) {}

    /**
     * @brief No-op in ring buffer design
     */
    void mark_workshares_kept_by_block(const std::vector<crypto::hash>& workshare_ids, bool kept) {}

    /**
     * @brief No-op in ring buffer design (automatic via overwriting)
     */
    void cleanup_expired() {}

    /**
     * @brief Get current pool statistics
     * @param total_workshares Output for total valid workshare count
     * @param active_parents Output for number of parent blocks with workshares
     */
    void get_pool_stats(size_t& total_workshares, size_t& active_parents);

    /**
     * @brief Check if workshare exists in pool (lock-free read)
     * @param id The workshare hash
     * @return true if exists, false otherwise
     */
    bool has_workshare(const crypto::hash& id);

    /**
     * @brief Get workshare IDs for inventory requests (lock-free read)
     * @param parent_block_id The parent block to query
     * @param max_count Maximum number of IDs to return
     * @return Vector of workshare IDs
     */
    std::vector<crypto::hash> get_workshare_inventory(
        const crypto::hash& parent_block_id, size_t max_count = MAX_WORKSHARES_PER_PARENT);

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

    // Reference to blockchain for validation
    Blockchain& m_blockchain;

    // Lock-free ring buffer storage
    // Each entry has an atomic valid flag to handle concurrent reads during writes
    struct ring_entry {
      std::atomic<bool> valid{false};
      workshare_pool_entry entry;
    };
    
    std::array<ring_entry, POOL_SIZE> m_ring_buffer;
    std::atomic<uint64_t> m_write_pos{0};
    
    // Statistics
    std::atomic<uint64_t> m_total_workshares{0};
  };
}
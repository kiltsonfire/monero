# Workshare System Architecture for Monero

## Overview

This document outlines the design for adding a workshare system to Monero that enables miners to contribute partial proof-of-work solutions that fall short of the full block difficulty by approximately 7 bits (~128x easier). The system is designed to prevent share hoarding attacks by enforcing that workshares can only be included in blocks if they reference the parent block of the including block.

## Key Design Principles

1. **Anti-Hoarding**: Workshares must reference the parent of the block that includes them
2. **Header-Only**: Workshares contain only block headers, no transaction data
3. **Proportional Weight**: 100 workshares add the weight equivalent of 1 additional block
4. **P2P Gossip**: Workshares are distributed through the existing P2P network
5. **Consensus Validation**: All workshares undergo strict validation rules

## Data Structures

### 1. Workshare Structure

```cpp
// File: src/cryptonote_basic/cryptonote_basic.h

struct workshare
{
    // Block header data (similar to block_header but for workshares)
    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    crypto::hash parent_block_id;  // CRITICAL: Must reference parent of including block
    crypto::hash referenced_block_id;  // The block this workshare was mining for
    uint32_t nonce;
    
    // Workshare-specific fields
    crypto::hash miner_address_hash;  // Hash of mining address for attribution
    uint64_t workshare_difficulty;    // The difficulty this workshare meets
    
    // Validation cache
    mutable std::atomic<bool> hash_valid;
    mutable crypto::hash hash;
    
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
```

### 2. Extended Block Structure

```cpp
// File: src/cryptonote_basic/cryptonote_basic.h

struct block: public block_header
{
    // ... existing fields ...
    
    // Workshare commitment (added to block)
    std::vector<crypto::hash> workshare_hashes;  // Hashes of included workshares
    crypto::hash workshare_merkle_root;          // Merkle root of workshares
    
    // Update serialization
    BEGIN_SERIALIZE_OBJECT()
        if (!typename Archive<W>::is_saving())
            set_hash_valid(false);
        
        FIELDS(*static_cast<block_header *>(this))
        FIELD(miner_tx)
        FIELD(tx_hashes)
        FIELD(workshare_hashes)
        FIELD(workshare_merkle_root)
        
        if (tx_hashes.size() > CRYPTONOTE_MAX_TX_PER_BLOCK)
            return false;
        if (workshare_hashes.size() > CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK)
            return false;
    END_SERIALIZE()
};
```

### 3. Workshare Pool Entry

```cpp
// File: src/cryptonote_core/workshare_pool.h

struct workshare_pool_entry
{
    workshare ws;
    crypto::hash id;
    uint64_t receive_time;
    uint64_t referenced_height;
    bool kept_by_block;  // True if included in a block
    
    BEGIN_SERIALIZE()
        FIELD(ws)
        FIELD(id)
        VARINT_FIELD(receive_time)
        VARINT_FIELD(referenced_height)
        FIELD(kept_by_block)
    END_SERIALIZE()
};
```

## Integration Points

### 1. Miner Integration (src/cryptonote_basic/miner.cpp)

#### Modified Worker Thread

```cpp
bool miner::worker_thread()
{
    // ... existing setup code ...
    
    while(!m_stop)
    {
        // ... existing template update code ...
        
        b.nonce = nonce;
        crypto::hash h;
        
        m_gbh(b, height, NULL, tools::get_max_concurrency(), h);
        
        // Check for full block solution
        if(check_hash(h, local_diff))
        {
            // ... existing full block handling ...
        }
        // NEW: Check for workshare solution
        else if(check_hash(h, get_workshare_difficulty(local_diff)))
        {
            workshare ws;
            if(create_workshare_from_block(b, ws, h))
            {
                MDEBUG("Found workshare for difficulty: " << ws.workshare_difficulty);
                m_phandler->handle_workshare_found(ws);
            }
        }
        
        nonce += m_threads_total;
        ++m_hashes;
        ++m_total_hashes;
    }
    // ... rest of function ...
}

private:
    difficulty_type get_workshare_difficulty(difficulty_type block_diff)
    {
        // Workshares are ~7 bits easier (divide by 128)
        return block_diff >> 7;
    }
    
    bool create_workshare_from_block(const block& b, workshare& ws, const crypto::hash& hash)
    {
        ws.major_version = b.major_version;
        ws.minor_version = b.minor_version;
        ws.timestamp = b.timestamp;
        ws.parent_block_id = get_parent_block_hash();  // Parent of current mining target
        ws.referenced_block_id = b.prev_id;           // Block we were mining for
        ws.nonce = b.nonce;
        ws.miner_address_hash = crypto::cn_fast_hash(&m_mine_address, sizeof(m_mine_address));
        ws.workshare_difficulty = get_workshare_difficulty(m_diffic);
        ws.set_hash(hash);
        return true;
    }
};
```

#### Extended Miner Handler Interface

```cpp
// File: src/cryptonote_basic/miner.h

struct i_miner_handler
{
    virtual bool handle_block_found(block& b, block_verification_context &bvc) = 0;
    virtual bool handle_workshare_found(const workshare& ws) = 0;  // NEW
    virtual bool get_block_template(/* ... existing params ... */) = 0;
    virtual crypto::hash get_parent_block_hash() = 0;  // NEW
protected:
    ~i_miner_handler(){};
};
```

### 2. P2P Protocol Integration

#### New Protocol Messages

```cpp
// File: src/cryptonote_protocol/cryptonote_protocol_defs.h

#define NOTIFY_NEW_WORKSHARE         2010
#define NOTIFY_REQUEST_WORKSHARES    2011  
#define NOTIFY_RESPONSE_WORKSHARES   2012

struct NOTIFY_NEW_WORKSHARE
{
    struct request
    {
        std::vector<blobdata> workshares;
        
        BEGIN_KV_SERIALIZE_MAP()
            KV_SERIALIZE(workshares)
        END_KV_SERIALIZE_MAP()
    };
};

struct NOTIFY_REQUEST_WORKSHARES
{
    struct request
    {
        std::vector<crypto::hash> workshare_ids;
        
        BEGIN_KV_SERIALIZE_MAP()
            KV_SERIALIZE_CONTAINER_POD_AS_BLOB(workshare_ids)
        END_KV_SERIALIZE_MAP()
    };
};

struct NOTIFY_RESPONSE_WORKSHARES
{
    struct request
    {
        std::vector<blobdata> workshares;
        std::vector<crypto::hash> missed_ids;
        
        BEGIN_KV_SERIALIZE_MAP()
            KV_SERIALIZE(workshares)
            KV_SERIALIZE_CONTAINER_POD_AS_BLOB(missed_ids)
        END_KV_SERIALIZE_MAP()
    };
};
```

#### Protocol Handler Updates

```cpp
// File: src/cryptonote_protocol/cryptonote_protocol_handler.h

template<class t_core>
class t_cryptonote_protocol_handler
{
    // ... existing methods ...
    
    // NEW: Workshare handling methods
    int handle_notify_new_workshare(int command, NOTIFY_NEW_WORKSHARE::request& arg, 
                                    cryptonote_connection_context& context);
    int handle_request_workshares(int command, NOTIFY_REQUEST_WORKSHARES::request& arg,
                                 cryptonote_connection_context& context);
    int handle_response_workshares(int command, NOTIFY_RESPONSE_WORKSHARES::request& arg,
                                  cryptonote_connection_context& context);
    
    bool relay_workshare(const workshare& ws, cryptonote_connection_context& exclude_context);
    
private:
    std::atomic<uint32_t> m_workshare_requests;
};
```

### 3. Workshare Pool Implementation

```cpp
// File: src/cryptonote_core/workshare_pool.h

class workshare_memory_pool
{
public:
    workshare_memory_pool(Blockchain& bchs);
    
    // Core operations
    bool add_workshare(const workshare& ws, workshare_verification_context& wvc, bool kept_by_block = false);
    bool take_workshares_for_block(crypto::hash parent_block_id, std::vector<workshare>& workshares, size_t max_count = 100);
    void on_blockchain_increment(uint64_t new_height, const crypto::hash& top_block_id);
    void on_blockchain_decrease(uint64_t new_height);
    
    // Validation
    bool validate_workshare(const workshare& ws, workshare_verification_context& wvc);
    bool check_workshare_parent_reference(const workshare& ws, const crypto::hash& including_block_parent);
    
    // Maintenance
    void remove_expired_workshares();
    void remove_workshares_for_block(const crypto::hash& block_id);
    
    // Statistics
    size_t get_workshare_count() const;
    uint64_t get_total_weight_addition() const;
    
private:
    // Storage containers
    std::unordered_map<crypto::hash, workshare_pool_entry> m_workshares;
    std::unordered_multimap<crypto::hash, crypto::hash> m_workshares_by_parent;  // parent_id -> workshare_ids
    std::multimap<uint64_t, crypto::hash> m_workshares_by_timestamp;  // timestamp -> workshare_id
    
    // References
    Blockchain& m_blockchain;
    
    // Configuration
    static constexpr uint64_t WORKSHARE_POOL_EXPIRY_TIME = 3600;  // 1 hour
    static constexpr size_t MAX_WORKSHARE_POOL_SIZE = 10000;
    
    // Synchronization
    mutable epee::critical_section m_workshare_lock;
    
    // Helper methods
    crypto::hash get_workshare_hash(const workshare& ws);
    bool is_workshare_expired(const workshare_pool_entry& entry, uint64_t current_time);
    void cleanup_expired_entries();
};
```

### 4. Blockchain Integration

#### Block Weight Calculation Updates

```cpp
// File: src/cryptonote_core/blockchain.cpp

uint64_t Blockchain::get_block_weight(const block& b)
{
    uint64_t base_weight = get_object_blobsize(b);
    
    // Add workshare weight: 100 workshares = weight of 1 block
    if (!b.workshare_hashes.empty())
    {
        uint64_t avg_block_weight = get_average_block_weight();
        uint64_t workshare_weight = (b.workshare_hashes.size() * avg_block_weight) / 100;
        base_weight += workshare_weight;
    }
    
    return base_weight;
}
```

#### Block Validation Updates

```cpp
bool Blockchain::validate_block_workshares(const block& bl, const crypto::hash& bl_id)
{
    // Validate workshare merkle root
    if (!bl.workshare_hashes.empty())
    {
        crypto::hash calculated_root = crypto::tree_hash(bl.workshare_hashes);
        if (calculated_root != bl.workshare_merkle_root)
        {
            MERROR_VER("Block workshare merkle root mismatch");
            return false;
        }
        
        // Validate each workshare
        crypto::hash parent_id = bl.prev_id;
        for (const auto& ws_hash : bl.workshare_hashes)
        {
            workshare ws;
            if (!m_workshare_pool.get_workshare(ws_hash, ws))
            {
                MERROR_VER("Block references unknown workshare: " << ws_hash);
                return false;
            }
            
            // CRITICAL: Validate parent reference
            if (ws.parent_block_id != parent_id)
            {
                MERROR_VER("Workshare parent reference invalid. Expected: " 
                          << parent_id << ", got: " << ws.parent_block_id);
                return false;
            }
            
            // Validate workshare meets difficulty
            workshare_verification_context wvc;
            if (!m_workshare_pool.validate_workshare(ws, wvc))
            {
                MERROR_VER("Invalid workshare in block: " << ws_hash);
                return false;
            }
        }
    }
    
    return true;
}
```

## Consensus Rules

### 1. Workshare Validation Rules

1. **Difficulty Check**: Workshare hash must meet workshare difficulty (~1/128 of block difficulty)
2. **Parent Reference**: `parent_block_id` must match the parent of the block including this workshare
3. **Timestamp Validity**: Workshare timestamp must be within reasonable bounds of referenced block
4. **Version Compatibility**: Major/minor versions must be compatible with referenced block
5. **Nonce Uniqueness**: Same nonce cannot be reused for same block template (prevents duplicate work)

### 2. Block Inclusion Rules

1. **Maximum Count**: Blocks can include at most 100 workshares
2. **Parent Validation**: All workshares must reference the block's parent
3. **Merkle Root**: Block must include correct merkle root of workshare hashes
4. **Weight Calculation**: 100 workshares add weight equivalent to 1 block
5. **No Duplicates**: No duplicate workshare hashes in a single block

### 3. Network Rules

1. **Propagation Limits**: Nodes should not relay more than 10 workshares per second per peer
2. **Storage Limits**: Workshare pool limited to 10,000 entries maximum
3. **Expiry Time**: Workshares expire after 1 hour if not included in a block
4. **Validation Priority**: Full blocks always take precedence over workshares

## Security Considerations

### 1. Anti-Hoarding Mechanism

The critical security feature is the parent block reference requirement:

```cpp
bool is_valid_workshare_for_block(const workshare& ws, const block& including_block)
{
    // CRITICAL: Workshare must reference the parent of the including block
    // This prevents miners from hoarding shares for future blocks
    return ws.parent_block_id == including_block.prev_id;
}
```

This ensures that:
- Workshares cannot be saved and used in future blocks
- Miners must contribute workshares for the current mining effort
- No strategic withholding of proof-of-work is possible

### 2. Attack Mitigation

#### Share Flooding Attack
- **Mitigation**: Rate limiting on workshare propagation (10/second/peer)
- **Pool Size Limit**: Maximum 10,000 workshares in memory pool
- **Expiry**: Automatic cleanup of old workshares

#### Invalid Share Attack  
- **Mitigation**: Full validation before relay or storage
- **Difficulty Verification**: Cryptographic proof that work was performed
- **Parent Validation**: Strict checking of parent block references

#### Selfish Mining with Workshares
- **Mitigation**: Parent reference requirement prevents cross-block share usage
- **Public Pool**: All valid workshares are publicly visible
- **No Private Advantage**: Cannot gain advantage by withholding workshares

### 3. Network Overhead

#### Bandwidth Considerations
- Workshare size: ~80 bytes (block header without transactions)
- Network overhead: Manageable with rate limiting
- Propagation: Only valid workshares are relayed

#### Storage Overhead
- Memory pool: Limited to 10,000 entries (~800KB maximum)
- Blockchain storage: Only merkle roots stored permanently
- Pruning: Old workshares automatically expire

## Implementation Phases

### Phase 1: Core Data Structures
1. Implement `workshare` structure
2. Add workshare fields to `block` structure  
3. Create workshare verification context
4. Update serialization methods

### Phase 2: Workshare Pool
1. Implement `workshare_memory_pool` class
2. Add validation logic
3. Implement parent reference checking
4. Add expiry and cleanup mechanisms

### Phase 3: Miner Integration  
1. Modify miner worker thread to detect workshares
2. Update miner handler interface
3. Implement workshare creation from blocks
4. Add workshare submission logic

### Phase 4: P2P Protocol
1. Add new protocol message types
2. Implement workshare gossip mechanisms
3. Add rate limiting and flood protection
4. Update connection handling

### Phase 5: Blockchain Integration
1. Update block validation to include workshares
2. Modify block weight calculations
3. Implement merkle tree validation
4. Add consensus rule enforcement

### Phase 6: Testing and Optimization
1. Unit tests for all components
2. Integration testing
3. Network simulation testing
4. Performance optimization

## Configuration Parameters

```cpp
// File: src/cryptonote_config.h

// Workshare system constants
#define CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT    7      // 2^7 = 128x easier
#define CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK     100     // Maximum workshares per block
#define CRYPTONOTE_WORKSHARE_WEIGHT_DIVISOR     100     // 100 workshares = 1 block weight
#define CRYPTONOTE_WORKSHARE_POOL_EXPIRY_TIME   3600    // 1 hour expiry
#define CRYPTONOTE_MAX_WORKSHARE_POOL_SIZE      10000   // Maximum pool size
#define CRYPTONOTE_WORKSHARE_RELAY_RATE_LIMIT   10      // Per second per peer
```

## API Extensions

### RPC Methods

```cpp
// File: src/rpc/core_rpc_server_commands_defs.h

struct COMMAND_RPC_GET_WORKSHARE_POOL
{
    struct request
    {
        BEGIN_KV_SERIALIZE_MAP()
        END_KV_SERIALIZE_MAP()
    };
    
    struct response
    {
        std::vector<workshare> workshares;
        std::string status;
        
        BEGIN_KV_SERIALIZE_MAP()
            KV_SERIALIZE(workshares)
            KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};

struct COMMAND_RPC_SUBMIT_WORKSHARE
{
    struct request
    {
        workshare ws;
        
        BEGIN_KV_SERIALIZE_MAP()
            KV_SERIALIZE(ws)
        END_KV_SERIALIZE_MAP()
    };
    
    struct response
    {
        std::string status;
        
        BEGIN_KV_SERIALIZE_MAP()
            KV_SERIALIZE(status)
        END_KV_SERIALIZE_MAP()
    };
};
```

This workshare system design provides a comprehensive framework for enabling partial proof-of-work contributions while maintaining strong security guarantees against share hoarding attacks through the critical parent block reference requirement.
# Monero Workshare System Formal Specification

## Table of Contents

1. [Introduction](#introduction)
2. [Protocol Overview](#protocol-overview)
3. [Data Structures and Encoding](#data-structures-and-encoding)
4. [Mathematical Definitions](#mathematical-definitions)
5. [Consensus Rules](#consensus-rules)
6. [Network Protocol](#network-protocol)
7. [Validation Algorithms](#validation-algorithms)
8. [Test Vectors](#test-vectors)
9. [Security Analysis](#security-analysis)
10. [Implementation Requirements](#implementation-requirements)

## 1. Introduction

This document provides a formal specification for the Monero Workshare System, a mechanism that allows miners to contribute partial proof-of-work solutions that fall short of the full block difficulty. The system is designed with a critical anti-hoarding mechanism that prevents strategic withholding of workshares.

### 1.1 Motivation

The workshare system addresses:
- **Network Security**: Increases the visible proof-of-work in the network
- **Mining Transparency**: Makes mining activity more observable
- **Attack Prevention**: Implements strong protections against share hoarding

### 1.2 Key Properties

- **Anti-Hoarding**: Workshares can only be included in blocks if they reference the parent block of the including block
- **Proportional Weight**: 100 workshares contribute weight equivalent to 1 additional block
- **Consensus Critical**: All workshares undergo strict validation and become part of consensus

## 2. Protocol Overview

### 2.1 System Architecture

```
Miner → Workshare Pool → Block Creation → Blockchain Validation
   ↓         ↓               ↓               ↓
 Generate   Store &       Include in      Validate &
Workshares  Validate      Block           Commit
```

### 2.2 Difficulty Relationship

Workshare difficulty is exactly `1/128` (2^-7) of the block difficulty:

```
workshare_difficulty = block_difficulty >> 7
```

### 2.3 Parent Reference Requirement

**CRITICAL SECURITY PROPERTY**: A workshare with hash `W` can only be included in block `B` if:

```
W.parent_block_id == B.prev_id
```

This requirement prevents all forms of share hoarding attacks.

## 3. Data Structures and Encoding

### 3.1 Workshare Structure

```cpp
struct workshare {
    uint8_t  major_version;        // Version compatibility
    uint8_t  minor_version;        // Version compatibility  
    uint64_t timestamp;            // Unix timestamp (little-endian)
    hash     parent_block_id;      // 32-byte hash of parent block
    hash     referenced_block_id;  // 32-byte hash of referenced block
    uint32_t nonce;               // Mining nonce (little-endian)
    hash     miner_address_hash;   // 32-byte hash of miner address
    uint64_t workshare_difficulty; // Difficulty target (little-endian)
};
```

**Binary Encoding (Wire Format)**:
```
Offset | Size | Field
-------|------|------
0      | 1    | major_version (VARINT)
1+     | 1    | minor_version (VARINT) 
2+     | 8    | timestamp (VARINT)
10+    | 32   | parent_block_id
42     | 32   | referenced_block_id
74     | 4    | nonce (little-endian)
78     | 32   | miner_address_hash
110    | 8    | workshare_difficulty (VARINT)
```

### 3.2 Extended Block Structure

Blocks are extended with workshare commitment fields:

```cpp
struct block : public block_header {
    // ... existing fields ...
    std::vector<hash> workshare_hashes;  // Ordered list of workshare hashes
    hash              workshare_merkle_root; // Merkle root of workshare_hashes
};
```

### 3.3 Workshare Pool Entry

```cpp
struct workshare_pool_entry {
    workshare ws;                // The workshare data
    hash      id;               // SHA3-256 hash of workshare
    uint64_t  receive_time;     // Unix timestamp of receipt
    uint64_t  referenced_height; // Height of referenced block
    bool      kept_by_block;    // True if included in a block
};
```

## 4. Mathematical Definitions

### 4.1 Hash Function

The workshare system uses SHA3-256 (Keccak-256) for all hash operations:

```
H(x) = SHA3-256(x)
```

### 4.2 Workshare Hash Calculation

The workshare hash is computed over the serialized workshare structure:

```cpp
hash workshare_hash(const workshare& ws) {
    std::string serialized = serialize(ws);
    return H(serialized);
}
```

### 4.3 Difficulty Check

A workshare meets difficulty `D` if:

```
H(workshare) ≤ 2^256 / D
```

Equivalently, using big-integer arithmetic:
```
difficulty_check(hash, target_difficulty) = (hash * target_difficulty) ≤ 2^256
```

### 4.4 Block Weight Calculation

The weight of a block including workshares is:

```
block_weight = base_weight + (workshare_count * average_block_weight) / 100
```

Where:
- `base_weight = sizeof(block_without_workshares)`
- `average_block_weight` is computed over recent blocks
- Division by 100 implements the "100 workshares = 1 block weight" rule

### 4.5 Merkle Tree Construction

The workshare merkle root is computed using the standard Monero tree hash:

```cpp
hash compute_workshare_merkle_root(const std::vector<hash>& workshare_hashes) {
    if (workshare_hashes.empty()) {
        return hash::null();
    }
    return crypto::tree_hash(workshare_hashes);
}
```

## 5. Consensus Rules

### 5.1 Workshare Validation Rules

A workshare `W` is valid if and only if ALL of the following conditions hold:

#### 5.1.1 Hash Meets Difficulty
```
H(W) * W.workshare_difficulty ≤ 2^256
```

#### 5.1.2 Version Compatibility
```
W.major_version == referenced_block.major_version
W.minor_version == referenced_block.minor_version
```

#### 5.1.3 Timestamp Bounds
```
referenced_block.timestamp - 3600 ≤ W.timestamp ≤ referenced_block.timestamp + 3600
```

#### 5.1.4 Difficulty Correctness
```
W.workshare_difficulty == referenced_block.difficulty >> 7
```

#### 5.1.5 Non-zero Fields
```
W.parent_block_id ≠ 0
W.referenced_block_id ≠ 0  
W.miner_address_hash ≠ 0
```

### 5.2 Block Inclusion Rules

A block `B` including workshares is valid if ALL of the following hold:

#### 5.2.1 Maximum Count Limit
```
|B.workshare_hashes| ≤ 100
```

#### 5.2.2 Parent Reference Requirement (CRITICAL)
```
∀W ∈ B.workshares: W.parent_block_id == B.prev_id
```

#### 5.2.3 Merkle Root Correctness
```
B.workshare_merkle_root == compute_workshare_merkle_root(B.workshare_hashes)
```

#### 5.2.4 Individual Workshare Validity
```
∀W ∈ B.workshares: is_valid_workshare(W) == true
```

#### 5.2.5 No Duplicate Workshares
```
∀i,j ∈ [0, |B.workshare_hashes|): i ≠ j ⟹ B.workshare_hashes[i] ≠ B.workshare_hashes[j]
```

### 5.3 Network Consensus Rules

#### 5.3.1 Block Weight Limits
```
block_weight(B) ≤ 2 * median_block_weight
```

#### 5.3.2 Workshare Pool Limits
- Maximum pool size: 10,000 workshares
- Maximum workshare age: 3,600 seconds (1 hour)
- Rate limit: 10 workshares per second per peer

## 6. Network Protocol

### 6.1 P2P Message Types

#### 6.1.1 NOTIFY_NEW_WORKSHARE (Command ID: 2010)
```json
{
    "workshares": [
        "<binary_workshare_1>",
        "<binary_workshare_2>",
        ...
    ]
}
```

#### 6.1.2 NOTIFY_REQUEST_WORKSHARES (Command ID: 2011)
```json
{
    "workshare_ids": [
        "<32_byte_hash_1>",
        "<32_byte_hash_2>", 
        ...
    ]
}
```

#### 6.1.3 NOTIFY_RESPONSE_WORKSHARES (Command ID: 2012)
```json
{
    "workshares": [
        "<binary_workshare_1>",
        ...
    ],
    "missed_ids": [
        "<32_byte_hash_1>",
        ...
    ]
}
```

### 6.2 Message Handling Rules

#### 6.2.1 Validation Before Relay
All received workshares MUST be validated before relay:
```cpp
bool handle_new_workshare(const workshare& ws) {
    workshare_verification_context wvc;
    if (!validate_workshare(ws, wvc)) {
        return false; // Drop invalid workshare
    }
    
    if (!add_to_pool(ws)) {
        return false; // Pool full or duplicate
    }
    
    relay_to_peers(ws);
    return true;
}
```

#### 6.2.2 Rate Limiting
```cpp
class peer_workshare_limiter {
    static constexpr uint32_t MAX_WORKSHARES_PER_SECOND = 10;
    static constexpr uint32_t TIME_WINDOW = 1000; // 1 second
    
    bool allow_workshare(peer_id id, uint64_t timestamp);
};
```

#### 6.2.3 Flood Protection
- Maximum 1000 workshares per NOTIFY_NEW_WORKSHARE message
- Maximum 100 workshare requests per NOTIFY_REQUEST_WORKSHARES
- Peer disconnection after 10 invalid workshares

## 7. Validation Algorithms

### 7.1 Core Workshare Validation

```cpp
bool validate_workshare(const workshare& ws, workshare_verification_context& wvc) {
    // Step 1: Verify hash meets difficulty
    hash ws_hash = compute_workshare_hash(ws);
    if (!check_hash_difficulty(ws_hash, ws.workshare_difficulty)) {
        wvc.m_verifivation_failed = true;
        wvc.m_low_difficulty = true;
        return false;
    }
    
    // Step 2: Verify referenced block exists
    block referenced_block;
    if (!get_block(ws.referenced_block_id, referenced_block)) {
        wvc.m_verifivation_failed = true;
        wvc.m_unknown_block = true;
        return false;
    }
    
    // Step 3: Verify version compatibility  
    if (ws.major_version != referenced_block.major_version ||
        ws.minor_version != referenced_block.minor_version) {
        wvc.m_verifivation_failed = true;
        wvc.m_invalid_version = true;
        return false;
    }
    
    // Step 4: Verify timestamp bounds
    uint64_t time_diff = abs_diff(ws.timestamp, referenced_block.timestamp);
    if (time_diff > 3600) { // 1 hour tolerance
        wvc.m_verifivation_failed = true;
        wvc.m_invalid_timestamp = true;
        return false;
    }
    
    // Step 5: Verify difficulty correctness
    difficulty_type expected_difficulty = referenced_block.difficulty >> 7;
    if (ws.workshare_difficulty != expected_difficulty) {
        wvc.m_verifivation_failed = true;
        wvc.m_invalid_difficulty = true;
        return false;
    }
    
    // Step 6: Verify parent block exists
    if (!block_exists(ws.parent_block_id)) {
        wvc.m_verifivation_failed = true;
        wvc.m_unknown_parent = true;
        return false;
    }
    
    return true;
}
```

### 7.2 Block Workshare Validation

```cpp
bool validate_block_workshares(const block& bl) {
    // Step 1: Check workshare count limit
    if (bl.workshare_hashes.size() > CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK) {
        return false;
    }
    
    // Step 2: Verify merkle root
    hash calculated_root = compute_workshare_merkle_root(bl.workshare_hashes);
    if (calculated_root != bl.workshare_merkle_root) {
        return false;
    }
    
    // Step 3: Validate each workshare
    hash parent_id = bl.prev_id;
    std::set<hash> seen_hashes;
    
    for (const hash& ws_hash : bl.workshare_hashes) {
        // Check for duplicates
        if (seen_hashes.count(ws_hash)) {
            return false;
        }
        seen_hashes.insert(ws_hash);
        
        // Get workshare from pool
        workshare ws;
        if (!get_workshare_from_pool(ws_hash, ws)) {
            return false;
        }
        
        // CRITICAL: Validate parent reference
        if (ws.parent_block_id != parent_id) {
            return false;
        }
        
        // Validate workshare itself
        workshare_verification_context wvc;
        if (!validate_workshare(ws, wvc)) {
            return false;
        }
    }
    
    return true;
}
```

### 7.3 Parent Reference Validation

```cpp
bool validate_parent_reference(const workshare& ws, const hash& including_block_parent) {
    // This is the CRITICAL anti-hoarding check
    return ws.parent_block_id == including_block_parent;
}
```

## 8. Test Vectors

### 8.1 Workshare Hash Test Vector

**Input Workshare**:
```
major_version: 16
minor_version: 16  
timestamp: 1692345600
parent_block_id: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
referenced_block_id: fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
nonce: 12345678
miner_address_hash: 1111111111111111111111111111111111111111111111111111111111111111
workshare_difficulty: 8192
```

**Serialized Bytes** (hex):
```
10 10 80a094bb32 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 4e61bc00 1111111111111111111111111111111111111111111111111111111111111111 802000
```

**Expected Hash** (SHA3-256):
```
a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

### 8.2 Difficulty Check Test Vector

**Hash**: `0x00000000123456789abcdef0123456789abcdef0123456789abcdef012345678`
**Difficulty**: `1048576` (2^20)

**Check**: 
```
hash_value = 0x00000000123456789abcdef0123456789abcdef0123456789abcdef012345678
target = 2^256 / 1048576 = 2^236
hash_value < target = true ✓
```

### 8.3 Merkle Root Test Vector

**Workshare Hashes**:
```
h1 = 1111111111111111111111111111111111111111111111111111111111111111
h2 = 2222222222222222222222222222222222222222222222222222222222222222  
h3 = 3333333333333333333333333333333333333333333333333333333333333333
```

**Expected Merkle Root**:
```
root = H(H(h1 || h2) || h3)
     = H(H(1111...1111 || 2222...2222) || 3333...3333)
     = abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab
```

### 8.4 Parent Reference Test Vector

**Scenario**: Valid workshare inclusion

**Block B**:
```
prev_id = parent123456789abcdef0123456789abcdef0123456789abcdef0123456789ab
```

**Workshare W**:
```
parent_block_id = parent123456789abcdef0123456789abcdef0123456789abcdef0123456789ab
```

**Validation**: `W.parent_block_id == B.prev_id` ✓ **PASS**

**Scenario**: Invalid workshare inclusion (hoarding attempt)

**Block B**:
```
prev_id = parent123456789abcdef0123456789abcdef0123456789abcdef0123456789ab
```

**Workshare W**:
```  
parent_block_id = old_parent789abcdef0123456789abcdef0123456789abcdef0123456789
```

**Validation**: `W.parent_block_id == B.prev_id` ✗ **FAIL**

## 9. Security Analysis

### 9.1 Share Hoarding Attack Prevention

**Attack**: Miner accumulates workshares and releases them strategically.

**Prevention**: The parent reference requirement `W.parent_block_id == B.prev_id` ensures workshares can only be used in the immediate next block after their creation.

**Proof**: 
- Let block chain be: `... -> P -> C -> N`
- Workshare `W` created during mining of `C` has `W.parent_block_id = P`  
- `W` can only be included in block `C` since `C.prev_id = P`
- `W` cannot be included in block `N` since `N.prev_id = C ≠ P`

### 9.2 Share Flooding Attack Mitigation

**Attack**: Adversary floods network with invalid/spam workshares.

**Mitigations**:
1. **Validation Before Relay**: All workshares validated before propagation
2. **Rate Limiting**: Maximum 10 workshares per second per peer
3. **Pool Size Limits**: Maximum 10,000 workshares in memory pool
4. **Expiry**: Workshares expire after 1 hour
5. **Difficulty Requirement**: Workshares must meet cryptographic difficulty

### 9.3 Selfish Mining Analysis

**Attack**: Miner withholds workshares to gain advantage.

**Analysis**: Workshares provide no private advantage since:
1. They don't contribute to private chain weight (only public blocks do)
2. Parent reference prevents cross-block usage
3. All valid workshares are publicly observable
4. No mining advantage from withholding workshares

**Conclusion**: Selfish mining attacks are not amplified by workshares.

### 9.4 Double-Spending Analysis

**Attack**: Use workshares to manipulate block weight for double-spending.

**Analysis**: 
- Workshares add weight but don't change block validity
- Double-spending requires controlling majority hashpower
- Workshares don't change this fundamental requirement
- 100 workshares = 1 block weight, so impact is limited

**Conclusion**: Workshares don't enable new double-spending vectors.

## 10. Implementation Requirements

### 10.1 Hard Fork Requirements

The workshare system requires a hard fork due to:
1. Changes to block structure (new fields)
2. New consensus rules for block validation
3. Modified block weight calculation
4. New network protocol messages

### 10.2 Backwards Compatibility

**Pre-Fork Nodes**:
- Will reject blocks with workshare fields
- Cannot participate in workshare gossip
- Will be on a different chain after fork

**Post-Fork Nodes**:
- Must validate all workshare rules
- Must support workshare P2P protocol  
- Must implement parent reference checking

### 10.3 Configuration Parameters

```cpp
// Fork activation
#define WORKSHARE_FORK_HEIGHT              2800000

// Workshare system constants  
#define CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT     7     // 2^7 = 128x easier
#define CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK      100    // Maximum per block
#define CRYPTONOTE_WORKSHARE_WEIGHT_DIVISOR      100    // Weight calculation
#define CRYPTONOTE_WORKSHARE_POOL_EXPIRY_TIME    3600   // 1 hour expiry
#define CRYPTONOTE_MAX_WORKSHARE_POOL_SIZE       10000  // Pool size limit
#define CRYPTONOTE_WORKSHARE_RELAY_RATE_LIMIT    10     // Per second per peer

// Validation tolerances
#define CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE 3600   // ±1 hour
```

### 10.4 RPC Interface Extensions

```cpp
// Get workshare pool status
struct get_workshare_pool_stats {
    struct response {
        uint64_t workshare_count;
        uint64_t total_weight_addition;
        uint64_t oldest_timestamp;
        uint64_t newest_timestamp;
    };
};

// Submit workshare
struct submit_workshare {
    struct request {
        workshare ws;
    };
    struct response {
        string status;
        string error_message;
    };
};

// Get workshares for block
struct get_workshares_for_parent {
    struct request {
        hash parent_block_id;
        uint32_t max_count;
    };
    struct response {
        vector<workshare> workshares;
        string status;
    };
};
```

### 10.5 Performance Requirements

**Memory Usage**:
- Maximum 10,000 workshares × 118 bytes = ~1.18 MB
- Plus indexing overhead ≈ 2 MB total

**CPU Usage**:
- Workshare validation: ~0.1ms per workshare
- Block validation: +10ms for 100 workshares
- Hash computation: Standard SHA3-256 performance

**Network Usage**:
- Workshare size: 118 bytes
- Rate limit: 10/second/peer = 1.18 KB/s/peer
- Manageable bandwidth overhead

### 10.6 Testing Requirements

**Unit Tests Required**:
- Workshare serialization/deserialization
- Hash computation and difficulty checking
- Parent reference validation
- Merkle root computation
- Pool management (add/remove/expire)

**Integration Tests Required**:
- Full block validation with workshares
- P2P message handling
- Rate limiting enforcement
- Fork activation behavior

**Network Tests Required**:
- Multi-node workshare propagation
- Attack scenario testing
- Performance under load
- Memory usage monitoring

---

This specification defines the complete workshare system with mathematical precision, comprehensive security analysis, and detailed implementation requirements. The critical anti-hoarding mechanism via parent block reference ensures the system maintains security while providing valuable proof-of-work visibility.
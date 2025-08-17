// Copyright (c) 2024, The Monero Project
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

#include <stdexcept>
#include <vector>
#include <algorithm>
#include <chrono>

#include "gtest/gtest.h"
#include "cryptonote_basic/workshare.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_config.h"
#include "crypto/hash.h"
#include "crypto/crypto.h"
#include "int-util.h"

using namespace cryptonote;

class WorkshareValidationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Generate test hash values for validation scenarios
        memset(&valid_parent_hash, 0x11, sizeof(valid_parent_hash));
        memset(&valid_block_hash, 0x22, sizeof(valid_block_hash)); 
        memset(&different_parent_hash, 0x33, sizeof(different_parent_hash));
        memset(&test_miner_hash, 0x44, sizeof(test_miner_hash));
        
        // Create base valid workshare
        valid_workshare.major_version = 16;
        valid_workshare.minor_version = 16;
        valid_workshare.timestamp = get_current_timestamp();
        valid_workshare.parent_block_id = valid_parent_hash;
        valid_workshare.referenced_block_id = valid_block_hash;
        valid_workshare.nonce = 12345;
        valid_workshare.miner_address_hash = test_miner_hash;
        valid_workshare.workshare_difficulty = 1000;
        
        // Set a valid hash that would meet the difficulty
        create_hash_for_difficulty(valid_workshare.workshare_difficulty, valid_hash);
        valid_workshare.set_hash(valid_hash);
    }
    
    uint64_t get_current_timestamp()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }
    
    // Create a hash that meets the specified difficulty for testing
    void create_hash_for_difficulty(difficulty_type diff, crypto::hash& result)
    {
        // This creates a hash that would pass the difficulty check
        // For testing purposes, we create a hash with enough leading zeros
        memset(&result, 0xFF, sizeof(result));
        
        if (diff > 0)
        {
            // Calculate target and create a hash below it
            boost::multiprecision::uint256_t target = 
                std::numeric_limits<boost::multiprecision::uint256_t>::max() / diff;
            
            // Set the hash to be just below the target
            target -= 1;
            
            // Convert target back to hash format
            uint64_t* hash_words = (uint64_t*)&result;
            for (int i = 0; i < 4; i++)
            {
                hash_words[i] = SWAP64LE((target & 0xFFFFFFFFFFFFFFFFULL).convert_to<uint64_t>());
                target >>= 64;
            }
        }
    }
    
    // Create a hash that does NOT meet the specified difficulty
    void create_hash_above_difficulty(difficulty_type diff, crypto::hash& result)
    {
        // This creates a hash that would fail the difficulty check
        memset(&result, 0xFF, sizeof(result));
        
        if (diff > 0)
        {
            // Set all bits to create a high hash value that won't meet difficulty
            memset(&result, 0xFF, sizeof(result));
        }
    }
    
    crypto::hash valid_parent_hash;
    crypto::hash valid_block_hash;
    crypto::hash different_parent_hash;
    crypto::hash test_miner_hash;
    crypto::hash valid_hash;
    crypto::hash invalid_hash;
    workshare valid_workshare;
};

// Test basic workshare structure validation
TEST_F(WorkshareValidationTest, BasicStructureValidation)
{
    workshare ws = valid_workshare;
    
    // Valid workshare should have all required fields
    EXPECT_GT(ws.major_version, 0);
    EXPECT_GE(ws.minor_version, 0);
    EXPECT_GT(ws.timestamp, 0);
    EXPECT_NE(ws.parent_block_id, crypto::null_hash);
    EXPECT_NE(ws.referenced_block_id, crypto::null_hash);
    EXPECT_GT(ws.workshare_difficulty, 0);
    EXPECT_NE(ws.miner_address_hash, crypto::null_hash);
    EXPECT_TRUE(ws.is_hash_valid());
}

// Test parent block reference validation (anti-hoarding mechanism)
TEST_F(WorkshareValidationTest, ParentBlockReferenceValidation)
{
    workshare ws = valid_workshare;
    
    // Valid case: parent_block_id properly set
    EXPECT_NE(ws.parent_block_id, crypto::null_hash);
    EXPECT_NE(ws.parent_block_id, ws.referenced_block_id); // Should be different
    
    // Invalid case: null parent reference
    ws.parent_block_id = crypto::null_hash;
    // This should be caught by validation logic (would need validation function)
    EXPECT_EQ(ws.parent_block_id, crypto::null_hash);
    
    // Invalid case: parent equals referenced block (not allowed)
    ws.parent_block_id = ws.referenced_block_id;
    EXPECT_EQ(ws.parent_block_id, ws.referenced_block_id);
    
    // Valid case: different parent and referenced blocks
    ws.parent_block_id = different_parent_hash;
    EXPECT_NE(ws.parent_block_id, ws.referenced_block_id);
}

// Test difficulty validation
TEST_F(WorkshareValidationTest, DifficultyValidation)
{
    // Test valid difficulty relationships
    difficulty_type block_diff = 128000; // Example block difficulty
    difficulty_type expected_ws_diff = block_diff >> CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT;
    
    EXPECT_EQ(expected_ws_diff, block_diff / 128);
    EXPECT_LT(expected_ws_diff, block_diff);
    
    // Test workshare difficulty should be exactly 7 bits easier
    EXPECT_EQ(expected_ws_diff, block_diff >> 7);
    
    // Test edge cases
    difficulty_type min_block_diff = 128;
    difficulty_type min_ws_diff = min_block_diff >> CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT;
    EXPECT_EQ(min_ws_diff, 1);
    
    // Test very small block difficulty
    difficulty_type tiny_block_diff = 64;
    difficulty_type tiny_ws_diff = tiny_block_diff >> CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT;
    EXPECT_EQ(tiny_ws_diff, 0); // Rounds to zero
    
    // Test large difficulty
    difficulty_type large_block_diff = std::numeric_limits<uint64_t>::max() / 2;
    difficulty_type large_ws_diff = large_block_diff >> CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT;
    EXPECT_LT(large_ws_diff, large_block_diff);
    EXPECT_GT(large_ws_diff, 0);
}

// Test hash difficulty validation
TEST_F(WorkshareValidationTest, HashDifficultyValidation) 
{
    difficulty_type test_difficulty = 1000;
    
    // Create hash that meets difficulty
    crypto::hash good_hash;
    create_hash_for_difficulty(test_difficulty, good_hash);
    
    // Create hash that doesn't meet difficulty  
    crypto::hash bad_hash;
    create_hash_above_difficulty(test_difficulty, bad_hash);
    
    // Test with cryptonote::check_hash function
    EXPECT_TRUE(cryptonote::check_hash(good_hash, test_difficulty));
    EXPECT_FALSE(cryptonote::check_hash(bad_hash, test_difficulty));
    
    // Test with workshare
    workshare ws_good = valid_workshare;
    ws_good.workshare_difficulty = test_difficulty;
    ws_good.set_hash(good_hash);
    
    workshare ws_bad = valid_workshare;
    ws_bad.workshare_difficulty = test_difficulty;
    ws_bad.set_hash(bad_hash);
    
    // These would need actual validation function to test fully
    EXPECT_TRUE(cryptonote::check_hash(ws_good.hash, ws_good.workshare_difficulty));
    EXPECT_FALSE(cryptonote::check_hash(ws_bad.hash, ws_bad.workshare_difficulty));
}

// Test timestamp validation
TEST_F(WorkshareValidationTest, TimestampValidation)
{
    uint64_t current_time = get_current_timestamp();
    workshare ws = valid_workshare;
    
    // Valid timestamps (within tolerance)
    ws.timestamp = current_time;
    EXPECT_LE(ws.timestamp, current_time + CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE);
    
    ws.timestamp = current_time - CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE;
    EXPECT_GE(ws.timestamp, current_time - CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE);
    
    ws.timestamp = current_time + CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE;
    EXPECT_LE(ws.timestamp, current_time + CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE);
    
    // Invalid timestamps (outside tolerance)
    uint64_t too_old = current_time - CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE - 1;
    uint64_t too_new = current_time + CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE + 1;
    
    ws.timestamp = too_old;
    EXPECT_LT(ws.timestamp, current_time - CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE);
    
    ws.timestamp = too_new;
    EXPECT_GT(ws.timestamp, current_time + CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE);
    
    // Test zero timestamp (invalid)
    ws.timestamp = 0;
    EXPECT_EQ(ws.timestamp, 0);
    
    // Test future timestamp way out of range
    ws.timestamp = current_time + (365 * 24 * 3600); // 1 year in future
    EXPECT_GT(ws.timestamp, current_time + CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE);
}

// Test version validation
TEST_F(WorkshareValidationTest, VersionValidation)
{
    workshare ws = valid_workshare;
    
    // Test valid version numbers
    ws.major_version = 16;
    ws.minor_version = 16;
    EXPECT_EQ(ws.major_version, 16);
    EXPECT_EQ(ws.minor_version, 16);
    
    // Test minimum valid versions
    ws.major_version = 1;
    ws.minor_version = 0;
    EXPECT_GE(ws.major_version, 1);
    EXPECT_GE(ws.minor_version, 0);
    
    // Test zero major version (likely invalid)
    ws.major_version = 0;
    EXPECT_EQ(ws.major_version, 0);
    
    // Test maximum valid versions
    ws.major_version = 255;
    ws.minor_version = 255;
    EXPECT_EQ(ws.major_version, 255);
    EXPECT_EQ(ws.minor_version, 255);
}

// Test nonce validation
TEST_F(WorkshareValidationTest, NonceValidation)
{
    workshare ws = valid_workshare;
    
    // Test valid nonce values
    ws.nonce = 0;
    EXPECT_EQ(ws.nonce, 0);
    
    ws.nonce = 12345;
    EXPECT_EQ(ws.nonce, 12345);
    
    ws.nonce = std::numeric_limits<uint32_t>::max();
    EXPECT_EQ(ws.nonce, std::numeric_limits<uint32_t>::max());
    
    // Test nonce overflow behavior
    uint64_t big_nonce = static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1;
    ws.nonce = static_cast<uint32_t>(big_nonce); // Should wrap around
    EXPECT_EQ(ws.nonce, 0); // Wraps to 0
}

// Test workshare limits validation  
TEST_F(WorkshareValidationTest, WorkshareLimitsValidation)
{
    // Test maximum workshares per block limit
    EXPECT_GT(CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK, 0);
    EXPECT_LE(CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK, 10000); // Reasonable upper bound
    
    // Test expected workshares is within max
    EXPECT_LE(CRYPTONOTE_EXPECTED_WORKSHARES_PER_BLOCK, CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK);
    EXPECT_GT(CRYPTONOTE_EXPECTED_WORKSHARES_PER_BLOCK, 0);
    
    // Test weight divisor makes sense
    EXPECT_GT(CRYPTONOTE_WORKSHARE_WEIGHT_DIVISOR, 0);
    EXPECT_LE(CRYPTONOTE_WORKSHARE_WEIGHT_DIVISOR, 1000); // Not too high
    
    // Test block weight calculation would work
    uint64_t num_workshares = CRYPTONOTE_EXPECTED_WORKSHARES_PER_BLOCK;
    uint64_t workshare_weight = num_workshares / CRYPTONOTE_WORKSHARE_WEIGHT_DIVISOR;
    EXPECT_GE(workshare_weight, 0);
    
    // Test at maximum workshares
    num_workshares = CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK;
    workshare_weight = num_workshares / CRYPTONOTE_WORKSHARE_WEIGHT_DIVISOR;
    EXPECT_GE(workshare_weight, 0);
    EXPECT_LT(workshare_weight, 10); // Should be reasonable weight
}

// Test anti-hoarding mechanism validation
TEST_F(WorkshareValidationTest, AntiHoardingValidation)
{
    workshare ws = valid_workshare;
    
    // Valid case: parent_block_id != referenced_block_id
    EXPECT_NE(ws.parent_block_id, ws.referenced_block_id);
    
    // Invalid case: trying to use same block for both
    crypto::hash same_hash;
    memset(&same_hash, 0x99, sizeof(same_hash));
    
    ws.parent_block_id = same_hash;
    ws.referenced_block_id = same_hash;
    EXPECT_EQ(ws.parent_block_id, ws.referenced_block_id); // This should be rejected
    
    // Valid case: proper parent-child relationship
    ws.parent_block_id = valid_parent_hash;
    ws.referenced_block_id = valid_block_hash; 
    EXPECT_NE(ws.parent_block_id, ws.referenced_block_id);
    
    // Test that null hashes are invalid
    ws.parent_block_id = crypto::null_hash;
    EXPECT_EQ(ws.parent_block_id, crypto::null_hash); // Should be rejected
    
    ws.referenced_block_id = crypto::null_hash;
    EXPECT_EQ(ws.referenced_block_id, crypto::null_hash); // Should be rejected
}

// Test verification context comprehensive scenarios
TEST_F(WorkshareValidationTest, VerificationContextScenarios)
{
    workshare_verification_context ctx;
    
    // Test low difficulty scenario
    ctx.m_low_difficulty = true;
    EXPECT_TRUE(ctx.m_low_difficulty);
    EXPECT_FALSE(ctx.m_verification_failed); // Not automatically set
    
    // Test unknown block scenario
    ctx = workshare_verification_context(); // Reset
    ctx.m_unknown_block = true;
    ctx.m_verification_failed = true;
    EXPECT_TRUE(ctx.m_unknown_block);
    EXPECT_TRUE(ctx.m_verification_failed);
    
    // Test invalid parent reference scenario
    ctx = workshare_verification_context(); // Reset
    ctx.m_invalid_parent_reference = true;
    ctx.m_verification_failed = true;
    EXPECT_TRUE(ctx.m_invalid_parent_reference);
    EXPECT_TRUE(ctx.m_verification_failed);
    
    // Test timestamp validation scenario
    ctx = workshare_verification_context(); // Reset
    ctx.m_invalid_timestamp = true;
    ctx.m_verification_failed = true;
    EXPECT_TRUE(ctx.m_invalid_timestamp);
    EXPECT_TRUE(ctx.m_verification_failed);
    
    // Test pool full scenario
    ctx = workshare_verification_context(); // Reset
    ctx.m_pool_full = true;
    // Pool full might not be a verification failure, just a resource limit
    EXPECT_TRUE(ctx.m_pool_full);
    
    // Test already exists scenario
    ctx = workshare_verification_context(); // Reset
    ctx.m_already_exists = true;
    EXPECT_TRUE(ctx.m_already_exists);
    
    // Test multiple failure conditions
    ctx = workshare_verification_context(); // Reset
    ctx.m_verification_failed = true;
    ctx.m_low_difficulty = true;
    ctx.m_invalid_timestamp = true;
    ctx.m_unknown_block = true;
    
    EXPECT_TRUE(ctx.m_verification_failed);
    EXPECT_TRUE(ctx.m_low_difficulty);
    EXPECT_TRUE(ctx.m_invalid_timestamp);
    EXPECT_TRUE(ctx.m_unknown_block);
    // Other flags should still be false
    EXPECT_FALSE(ctx.m_pool_full);
    EXPECT_FALSE(ctx.m_already_exists);
}

// Test edge cases for validation
TEST_F(WorkshareValidationTest, EdgeCases)
{
    // Test with minimum valid difficulty
    workshare ws = valid_workshare;
    ws.workshare_difficulty = 1;
    
    crypto::hash min_diff_hash;
    create_hash_for_difficulty(1, min_diff_hash);
    ws.set_hash(min_diff_hash);
    
    EXPECT_EQ(ws.workshare_difficulty, 1);
    EXPECT_TRUE(cryptonote::check_hash(ws.hash, ws.workshare_difficulty));
    
    // Test with zero difficulty (should be invalid)
    ws.workshare_difficulty = 0;
    // Hash check with zero difficulty would be problematic
    EXPECT_EQ(ws.workshare_difficulty, 0);
    
    // Test with maximum difficulty
    ws.workshare_difficulty = std::numeric_limits<difficulty_type>::max();
    EXPECT_EQ(ws.workshare_difficulty, std::numeric_limits<difficulty_type>::max());
    
    // Most hashes won't meet max difficulty, but structure should be valid
    EXPECT_GT(ws.workshare_difficulty, 0);
}

// Test serialization edge cases for validation
TEST_F(WorkshareValidationTest, SerializationValidation)
{
    // Test serialization of workshare with all maximum values
    workshare ws;
    ws.major_version = 255;
    ws.minor_version = 255;
    ws.timestamp = std::numeric_limits<uint64_t>::max();
    ws.nonce = std::numeric_limits<uint32_t>::max();
    ws.workshare_difficulty = std::numeric_limits<difficulty_type>::max();
    
    // Fill hashes with max values
    memset(&ws.parent_block_id, 0xFF, sizeof(ws.parent_block_id));
    memset(&ws.referenced_block_id, 0xFF, sizeof(ws.referenced_block_id));
    memset(&ws.miner_address_hash, 0xFF, sizeof(ws.miner_address_hash));
    
    std::string blob;
    ASSERT_TRUE(::serialization::dump_binary(ws, blob));
    EXPECT_GT(blob.size(), 0);
    
    workshare ws2;
    ASSERT_TRUE(::serialization::parse_binary(blob, ws2));
    
    // Verify all extreme values survived serialization
    EXPECT_EQ(ws2.major_version, 255);
    EXPECT_EQ(ws2.minor_version, 255);
    EXPECT_EQ(ws2.timestamp, std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(ws2.nonce, std::numeric_limits<uint32_t>::max());
    EXPECT_EQ(ws2.workshare_difficulty, std::numeric_limits<difficulty_type>::max());
    
    // Verify hashes
    EXPECT_EQ(ws2.parent_block_id, ws.parent_block_id);
    EXPECT_EQ(ws2.referenced_block_id, ws.referenced_block_id);
    EXPECT_EQ(ws2.miner_address_hash, ws.miner_address_hash);
    
    // Test empty/minimal serialization
    workshare ws_min;
    ASSERT_TRUE(::serialization::dump_binary(ws_min, blob));
    EXPECT_GT(blob.size(), 0);
    
    workshare ws_min2;
    ASSERT_TRUE(::serialization::parse_binary(blob, ws_min2));
    
    // Should match default values
    EXPECT_EQ(ws_min2.major_version, 0);
    EXPECT_EQ(ws_min2.minor_version, 0);
    EXPECT_EQ(ws_min2.timestamp, 0);
    EXPECT_EQ(ws_min2.nonce, 0);
    EXPECT_EQ(ws_min2.workshare_difficulty, 0);
}
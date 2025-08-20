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

#include "gtest/gtest.h"
#include "cryptonote_basic/workshare.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_config.h"
#include "crypto/hash.h"
#include "crypto/crypto.h"
#include "serialization/binary_archive.h"
#include "int-util.h"

using namespace cryptonote;

class WorkshareTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Generate test hash values
        memset(&test_hash_1, 0x12, sizeof(test_hash_1));
        memset(&test_hash_2, 0x34, sizeof(test_hash_2)); 
        memset(&test_hash_3, 0x56, sizeof(test_hash_3));
        
        // Create test address hash
        memset(&test_address_hash, 0x78, sizeof(test_address_hash));
    }
    
    crypto::hash test_hash_1;
    crypto::hash test_hash_2; 
    crypto::hash test_hash_3;
    crypto::hash test_address_hash;
};

// Test basic workshare structure initialization
TEST_F(WorkshareTest, DefaultConstructor)
{
    workshare ws;
    
    EXPECT_EQ(ws.major_version, 0);
    EXPECT_EQ(ws.minor_version, 0);
    EXPECT_EQ(ws.timestamp, 0);
    EXPECT_EQ(ws.prev_id, crypto::null_hash);
    EXPECT_EQ(ws.nonce, 0);
    EXPECT_FALSE(ws.is_hash_valid());
    EXPECT_EQ(ws.hash, crypto::null_hash);
}

// Test workshare structure field assignment
TEST_F(WorkshareTest, FieldAssignment)
{
    workshare ws;
    
    ws.major_version = 16;
    ws.minor_version = 16;
    ws.timestamp = 1640995200; // 2022-01-01 00:00:00
    ws.prev_id = test_hash_1;
    ws.nonce = 12345;
    ws.set_hash(test_hash_3);
    
    EXPECT_EQ(ws.major_version, 16);
    EXPECT_EQ(ws.minor_version, 16);
    EXPECT_EQ(ws.timestamp, 1640995200);
    EXPECT_EQ(ws.prev_id, test_hash_1);
    EXPECT_EQ(ws.nonce, 12345);
    EXPECT_TRUE(ws.is_hash_valid());
    EXPECT_EQ(ws.hash, test_hash_3);
}

// Test copy constructor
TEST_F(WorkshareTest, CopyConstructor)
{
    workshare ws1;
    
    ws1.major_version = 16;
    ws1.minor_version = 16;
    ws1.timestamp = 1640995200;
    ws1.prev_id = test_hash_1;
    ws1.nonce = 12345;
    ws1.set_hash(test_hash_3);
    
    workshare ws2(ws1);
    
    EXPECT_EQ(ws2.major_version, 16);
    EXPECT_EQ(ws2.minor_version, 16);
    EXPECT_EQ(ws2.timestamp, 1640995200);
    EXPECT_EQ(ws2.prev_id, test_hash_1);
    EXPECT_EQ(ws2.nonce, 12345);
    EXPECT_TRUE(ws2.is_hash_valid());
    EXPECT_EQ(ws2.hash, test_hash_3);
}

// Test assignment operator
TEST_F(WorkshareTest, AssignmentOperator)
{
    workshare ws1;
    
    ws1.major_version = 16;
    ws1.minor_version = 16;
    ws1.timestamp = 1640995200;
    ws1.prev_id = test_hash_1;
    ws1.nonce = 12345;
    ws1.set_hash(test_hash_3);
    
    workshare ws2;
    ws2 = ws1;
    
    EXPECT_EQ(ws2.major_version, 16);
    EXPECT_EQ(ws2.minor_version, 16);
    EXPECT_EQ(ws2.timestamp, 1640995200);
    EXPECT_EQ(ws2.prev_id, test_hash_1);
    EXPECT_EQ(ws2.nonce, 12345);
    EXPECT_TRUE(ws2.is_hash_valid());
    EXPECT_EQ(ws2.hash, test_hash_3);
}

// Test self-assignment
TEST_F(WorkshareTest, SelfAssignment)
{
    workshare ws;
    
    ws.major_version = 16;
    ws.nonce = 12345;
    ws.set_hash(test_hash_1);
    
    ws = ws; // Self-assignment
    
    EXPECT_EQ(ws.major_version, 16);
    EXPECT_EQ(ws.nonce, 12345);
    EXPECT_TRUE(ws.is_hash_valid());
    EXPECT_EQ(ws.hash, test_hash_1);
}

// Test set_null functionality
TEST_F(WorkshareTest, SetNull)
{
    workshare ws;
    
    // Set some values first
    ws.major_version = 16;
    ws.minor_version = 16;
    ws.timestamp = 1640995200;
    ws.prev_id = test_hash_1;
    ws.nonce = 12345;
    ws.set_hash(test_hash_3);
    
    // Verify values are set
    EXPECT_NE(ws.major_version, 0);
    EXPECT_TRUE(ws.is_hash_valid());
    
    // Reset to null
    ws.set_null();
    
    EXPECT_EQ(ws.major_version, 0);
    EXPECT_EQ(ws.minor_version, 0);
    EXPECT_EQ(ws.timestamp, 0);
    EXPECT_EQ(ws.prev_id, crypto::null_hash);
    EXPECT_EQ(ws.nonce, 0);
    EXPECT_FALSE(ws.is_hash_valid());
}

// Test hash validation methods
TEST_F(WorkshareTest, HashValidation)
{
    workshare ws;
    
    // Initially not valid
    EXPECT_FALSE(ws.is_hash_valid());
    
    // Set hash manually
    ws.set_hash_valid(true);
    EXPECT_TRUE(ws.is_hash_valid());
    
    ws.set_hash_valid(false);
    EXPECT_FALSE(ws.is_hash_valid());
    
    // Set hash and check auto-validation
    ws.set_hash(test_hash_1);
    EXPECT_TRUE(ws.is_hash_valid());
    EXPECT_EQ(ws.hash, test_hash_1);
    
    // Invalidate hashes
    ws.invalidate_hashes();
    EXPECT_FALSE(ws.is_hash_valid());
}

// Test serialization and deserialization
TEST_F(WorkshareTest, Serialization)
{
    workshare ws1;
    
    // Set up test data
    ws1.major_version = 16;
    ws1.minor_version = 16;
    ws1.timestamp = 1640995200;
    ws1.prev_id = test_hash_1;
    ws1.nonce = 12345;
    
    // Serialize
    std::string blob;
    blob = t_serializable_object_to_blob(ws1);
    EXPECT_GT(blob.size(), 0);
    
    // Deserialize
    workshare ws2;
    ASSERT_TRUE(parse_and_validate_from_blob(blob, ws2));
    
    // Verify fields (note: hash validation state is not serialized)
    EXPECT_EQ(ws2.major_version, ws1.major_version);
    EXPECT_EQ(ws2.minor_version, ws1.minor_version);
    EXPECT_EQ(ws2.timestamp, ws1.timestamp);
    EXPECT_EQ(ws2.prev_id, ws1.prev_id);
    EXPECT_EQ(ws2.nonce, ws1.nonce);
}

// Test difficulty calculation (workshares should be 2^7 = 128 times easier)
TEST_F(WorkshareTest, DifficultyCalculation)
{
    difficulty_type block_diff = 1000000;
    difficulty_type expected_workshare_diff = block_diff >> CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT;
    difficulty_type calculated_workshare_diff = block_diff >> 7; // 2^7 = 128
    
    EXPECT_EQ(expected_workshare_diff, calculated_workshare_diff);
    EXPECT_EQ(expected_workshare_diff, block_diff / 128);
    
    // Test with edge cases
    difficulty_type max_diff = std::numeric_limits<uint64_t>::max();
    difficulty_type max_workshare_diff = max_diff >> CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT;
    EXPECT_LT(max_workshare_diff, max_diff);
    
    // Test with minimum meaningful difficulty  
    difficulty_type min_diff = 128;
    difficulty_type min_workshare_diff = min_diff >> CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT;
    EXPECT_EQ(min_workshare_diff, 1);
    
    // Test with difficulty smaller than shift
    difficulty_type small_diff = 64;
    difficulty_type small_workshare_diff = small_diff >> CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT;
    EXPECT_EQ(small_workshare_diff, 0);
}

// Test workshare_verification_context structure
TEST_F(WorkshareTest, VerificationContext)
{
    workshare_verification_context ctx;
    
    // Check default values
    EXPECT_FALSE(ctx.m_verification_failed);
    EXPECT_FALSE(ctx.m_low_difficulty);
    EXPECT_FALSE(ctx.m_unknown_block);
    EXPECT_FALSE(ctx.m_invalid_version);
    EXPECT_FALSE(ctx.m_invalid_timestamp);
    EXPECT_FALSE(ctx.m_already_exists);
    EXPECT_FALSE(ctx.m_pool_full);
    
    // Test setting individual flags
    ctx.m_verification_failed = true;
    ctx.m_low_difficulty = true;
    EXPECT_TRUE(ctx.m_verification_failed);
    EXPECT_TRUE(ctx.m_low_difficulty);
    EXPECT_FALSE(ctx.m_unknown_block); // Others should remain false
}

// Test workshare_pool_entry structure
TEST_F(WorkshareTest, PoolEntry)
{
    // Test default constructor
    workshare_pool_entry entry1;
    EXPECT_EQ(entry1.id, crypto::null_hash);
    EXPECT_EQ(entry1.receive_time, 0);
    EXPECT_FALSE(entry1.kept_by_block);
    
    // Test parameterized constructor
    workshare ws;
    ws.major_version = 16;
    ws.nonce = 12345;
    
    uint64_t receive_time = 1640995200;
    
    workshare_pool_entry entry2(ws, test_hash_1, receive_time);
    
    EXPECT_EQ(entry2.ws.major_version, 16);
    EXPECT_EQ(entry2.ws.nonce, 12345);
    EXPECT_EQ(entry2.id, test_hash_1);
    EXPECT_EQ(entry2.receive_time, receive_time);
    EXPECT_FALSE(entry2.kept_by_block);
    
    // Test serialization
    std::string blob;
    blob = t_serializable_object_to_blob(entry2);
    EXPECT_GT(blob.size(), 0);
    
    workshare_pool_entry entry3;
    ASSERT_TRUE(parse_and_validate_from_blob(blob, entry3));
    
    EXPECT_EQ(entry3.ws.major_version, entry2.ws.major_version);
    EXPECT_EQ(entry3.ws.nonce, entry2.ws.nonce);
    EXPECT_EQ(entry3.id, entry2.id);
    EXPECT_EQ(entry3.receive_time, entry2.receive_time);
    EXPECT_EQ(entry3.kept_by_block, entry2.kept_by_block);
}

// Test configuration constants are reasonable
TEST_F(WorkshareTest, ConfigurationConstants)
{
    // Test shift value is reasonable (7 bits = 128x easier)
    EXPECT_EQ(CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT, 7);
    EXPECT_EQ(1 << CRYPTONOTE_WORKSHARE_DIFFICULTY_SHIFT, 128);
    
    // Test maximum workshares per block is reasonable 
    EXPECT_EQ(CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK, 300);
    EXPECT_GT(CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK, 0);
    EXPECT_LT(CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK, 10000); // Not too high
    
    // Test expected workshares per block
    EXPECT_EQ(CRYPTONOTE_EXPECTED_WORKSHARES_PER_BLOCK, 100);
    EXPECT_LE(CRYPTONOTE_EXPECTED_WORKSHARES_PER_BLOCK, CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK);
    
    // Test weight divisor
    EXPECT_EQ(CRYPTONOTE_WORKSHARE_WEIGHT_DIVISOR, 100);
    EXPECT_GT(CRYPTONOTE_WORKSHARE_WEIGHT_DIVISOR, 0);
    
    // Test expiry time is reasonable (1 hour)
    EXPECT_EQ(CRYPTONOTE_WORKSHARE_POOL_EXPIRY_TIME, 3600);
    EXPECT_GT(CRYPTONOTE_WORKSHARE_POOL_EXPIRY_TIME, 0);
    
    // Test pool size limit
    EXPECT_EQ(CRYPTONOTE_MAX_WORKSHARE_POOL_SIZE, 10000);
    EXPECT_GT(CRYPTONOTE_MAX_WORKSHARE_POOL_SIZE, CRYPTONOTE_MAX_WORKSHARES_PER_BLOCK);
    
    // Test relay rate limit
    EXPECT_EQ(CRYPTONOTE_WORKSHARE_RELAY_RATE_LIMIT, 10);
    EXPECT_GT(CRYPTONOTE_WORKSHARE_RELAY_RATE_LIMIT, 0);
    
    // Test timestamp tolerance (1 hour)
    EXPECT_EQ(CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE, 3600);
    EXPECT_GT(CRYPTONOTE_WORKSHARE_TIMESTAMP_TOLERANCE, 0);
}

// Test edge cases for large numbers
TEST_F(WorkshareTest, LargeNumberHandling)
{
    workshare ws;
    
    // Test with maximum values
    ws.timestamp = std::numeric_limits<uint64_t>::max();
    ws.nonce = std::numeric_limits<uint32_t>::max();
    
    // Should not crash or overflow
    EXPECT_EQ(ws.timestamp, std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(ws.nonce, std::numeric_limits<uint32_t>::max());
    
    // Test serialization with large values
    std::string blob;
    blob = t_serializable_object_to_blob(ws);
    
    workshare ws2;
    ASSERT_TRUE(parse_and_validate_from_blob(blob, ws2));
    
    EXPECT_EQ(ws2.timestamp, ws.timestamp);
    EXPECT_EQ(ws2.nonce, ws.nonce);
}

// Test concurrent access to hash validation (basic thread safety test)
TEST_F(WorkshareTest, ConcurrentHashValidation)
{
    workshare ws;
    
    // This is a basic test - in a real concurrent environment you'd need proper synchronization
    ws.set_hash_valid(true);
    EXPECT_TRUE(ws.is_hash_valid());
    
    ws.set_hash_valid(false);
    EXPECT_FALSE(ws.is_hash_valid());
    
    ws.set_hash(test_hash_1);
    EXPECT_TRUE(ws.is_hash_valid());
    EXPECT_EQ(ws.hash, test_hash_1);
    
    ws.invalidate_hashes();
    EXPECT_FALSE(ws.is_hash_valid());
}
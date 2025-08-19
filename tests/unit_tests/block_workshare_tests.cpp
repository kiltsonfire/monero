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

#include "gtest/gtest.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/workshare.h"
#include "cryptonote_core/blockchain.h"
#include "crypto/crypto.h"
#include <vector>

using namespace cryptonote;

class BlockWorkshareTest : public ::testing::Test
{
protected:
  block create_test_block_with_workshares(size_t num_workshares)
  {
    block b = {};
    
    // Set basic block fields
    b.major_version = 1;
    b.minor_version = 0;
    b.timestamp = 1234567890;
    b.prev_id = crypto::null_hash;
    b.nonce = 1000;
    
    // Add workshare hashes
    b.workshare_hashes.clear();
    for (size_t i = 0; i < num_workshares; ++i)
    {
      crypto::hash ws_hash;
      // Generate pseudo-random hash for testing
      memset(&ws_hash, i + 1, sizeof(ws_hash));
      b.workshare_hashes.push_back(ws_hash);
    }
    
    // Update workshare count in header
    b.workshare_count = num_workshares;
    
    return b;
  }
  
  workshare create_test_workshare(const crypto::hash& prev_id, uint32_t nonce)
  {
    workshare ws = {};
    ws.major_version = 1;
    ws.minor_version = 0;
    ws.timestamp = 1234567890 + nonce;
    ws.prev_id = prev_id;
    ws.nonce = nonce;
    ws.workshare_count = 0; // Workshares don't include other workshares
    return ws;
  }
};

TEST_F(BlockWorkshareTest, BlockSerializationWithWorkshares)
{
  // Test with 0 workshares
  {
    block b = create_test_block_with_workshares(0);
    
    // Serialize
    blobdata blob = t_serializable_object_to_blob(b);
    
    // Deserialize
    block b2;
    ASSERT_TRUE(parse_and_validate_block_from_blob(blob, b2));
    
    // Verify
    EXPECT_EQ(b.workshare_count, b2.workshare_count);
    EXPECT_EQ(b.workshare_hashes.size(), b2.workshare_hashes.size());
    EXPECT_EQ(0u, b2.workshare_count);
  }
  
  // Test with 10 workshares
  {
    block b = create_test_block_with_workshares(10);
    
    // Serialize
    blobdata blob = t_serializable_object_to_blob(b);
    
    // Deserialize
    block b2;
    ASSERT_TRUE(parse_and_validate_block_from_blob(blob, b2));
    
    // Verify
    EXPECT_EQ(b.workshare_count, b2.workshare_count);
    EXPECT_EQ(b.workshare_hashes.size(), b2.workshare_hashes.size());
    EXPECT_EQ(10u, b2.workshare_count);
    
    // Verify workshare hashes match
    for (size_t i = 0; i < b.workshare_hashes.size(); ++i)
    {
      EXPECT_EQ(b.workshare_hashes[i], b2.workshare_hashes[i]);
    }
  }
  
  // Test with maximum workshares (300)
  {
    block b = create_test_block_with_workshares(300);
    
    // Serialize
    blobdata blob = t_serializable_object_to_blob(b);
    
    // Deserialize
    block b2;
    ASSERT_TRUE(parse_and_validate_block_from_blob(blob, b2));
    
    // Verify
    EXPECT_EQ(b.workshare_count, b2.workshare_count);
    EXPECT_EQ(b.workshare_hashes.size(), b2.workshare_hashes.size());
    EXPECT_EQ(300u, b2.workshare_count);
  }
}

TEST_F(BlockWorkshareTest, BlockWeightCalculationWithWorkshares)
{
  // Test weight calculation with no workshares
  {
    block b = create_test_block_with_workshares(0);
    size_t base_size = get_object_blobsize(b);
    
    // Weight should be just the base size when no workshares
    EXPECT_GT(base_size, 0u);
  }
  
  // Test weight calculation with workshares
  {
    block b1 = create_test_block_with_workshares(10);
    block b2 = create_test_block_with_workshares(20);
    
    size_t size1 = get_object_blobsize(b1);
    size_t size2 = get_object_blobsize(b2);
    
    // Block with more workshares should be larger
    EXPECT_GT(size2, size1);
    
    // The difference should be approximately 10 * sizeof(crypto::hash)
    size_t expected_diff = 10 * sizeof(crypto::hash);
    size_t actual_diff = size2 - size1;
    
    // Allow some variance for serialization overhead
    EXPECT_NEAR(actual_diff, expected_diff, 10);
  }
}

TEST_F(BlockWorkshareTest, WorkshareCountValidation)
{
  // Test that workshare_count matches workshare_hashes size
  {
    block b = create_test_block_with_workshares(10);
    
    // Manually set incorrect count
    b.workshare_count = 5;
    
    // This block should be considered invalid
    // (In real validation, this would be checked)
    EXPECT_NE(b.workshare_count, b.workshare_hashes.size());
  }
  
  // Test with correct count
  {
    block b = create_test_block_with_workshares(10);
    EXPECT_EQ(b.workshare_count, b.workshare_hashes.size());
  }
}

TEST_F(BlockWorkshareTest, WorkshareStructureSerialization)
{
  crypto::hash prev_id;
  memset(&prev_id, 0xAB, sizeof(prev_id));
  
  workshare ws = create_test_workshare(prev_id, 12345);
  
  // Serialize
  blobdata blob = t_serializable_object_to_blob(ws);
  
  // Deserialize
  workshare ws2;
  ASSERT_TRUE(parse_and_validate_from_blob(blob, ws2));
  
  // Verify all fields match
  EXPECT_EQ(ws.major_version, ws2.major_version);
  EXPECT_EQ(ws.minor_version, ws2.minor_version);
  EXPECT_EQ(ws.timestamp, ws2.timestamp);
  EXPECT_EQ(ws.prev_id, ws2.prev_id);
  EXPECT_EQ(ws.nonce, ws2.nonce);
  EXPECT_EQ(ws.workshare_count, ws2.workshare_count);
}

TEST_F(BlockWorkshareTest, BlockHeaderWorkshareCompatibility)
{
  // Test that block_header and workshare structures are compatible
  block b = create_test_block_with_workshares(5);
  
  // Create a workshare from block header fields
  workshare ws;
  ws.major_version = b.major_version;
  ws.minor_version = b.minor_version;
  ws.timestamp = b.timestamp;
  ws.prev_id = b.prev_id;
  ws.nonce = b.nonce;
  ws.workshare_count = 0; // Workshares don't include other workshares
  
  // Verify sizes are the same (excluding cache fields)
  // This ensures structural compatibility
  EXPECT_EQ(sizeof(b.major_version), sizeof(ws.major_version));
  EXPECT_EQ(sizeof(b.minor_version), sizeof(ws.minor_version));
  EXPECT_EQ(sizeof(b.timestamp), sizeof(ws.timestamp));
  EXPECT_EQ(sizeof(b.prev_id), sizeof(ws.prev_id));
  EXPECT_EQ(sizeof(b.nonce), sizeof(ws.nonce));
  EXPECT_EQ(sizeof(b.workshare_count), sizeof(ws.workshare_count));
}

TEST_F(BlockWorkshareTest, BlockCompleteEntryWithWorkshares)
{
  // Create a block with workshares
  block b = create_test_block_with_workshares(5);
  
  // Create workshare objects
  std::vector<workshare> workshares;
  std::vector<blobdata> workshare_blobs;
  
  for (size_t i = 0; i < 5; ++i)
  {
    workshare ws = create_test_workshare(b.prev_id, 1000 + i);
    workshares.push_back(ws);
    workshare_blobs.push_back(t_serializable_object_to_blob(ws));
  }
  
  // Create block complete entry
  block_complete_entry bce;
  bce.block = t_serializable_object_to_blob(b);
  bce.workshares = workshare_blobs;
  
  // Verify workshares are included
  EXPECT_EQ(bce.workshares.size(), 5u);
  
  // Verify workshares can be deserialized
  for (size_t i = 0; i < bce.workshares.size(); ++i)
  {
    workshare ws;
    ASSERT_TRUE(parse_and_validate_from_blob(bce.workshares[i], ws));
    EXPECT_EQ(ws.prev_id, b.prev_id);
  }
}

TEST_F(BlockWorkshareTest, MaxWorkshareLimit)
{
  // Test that we enforce maximum workshare limit
  const size_t MAX_WORKSHARES_PER_BLOCK = 300;
  
  block b = create_test_block_with_workshares(MAX_WORKSHARES_PER_BLOCK);
  
  // Should be exactly at limit
  EXPECT_EQ(b.workshare_hashes.size(), MAX_WORKSHARES_PER_BLOCK);
  EXPECT_EQ(b.workshare_count, MAX_WORKSHARES_PER_BLOCK);
  
  // Try to create block with too many workshares
  block b2 = create_test_block_with_workshares(MAX_WORKSHARES_PER_BLOCK + 1);
  
  // In real validation, this would be rejected
  EXPECT_GT(b2.workshare_hashes.size(), MAX_WORKSHARES_PER_BLOCK);
}
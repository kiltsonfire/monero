#!/usr/bin/env python3
import re
import json
import subprocess
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

def parse_logs(log_file):
    """Parse log file to extract workshare and block information"""
    
    # Track all workshares found/added
    workshares_by_height = defaultdict(set)  # height -> set of workshare hashes
    blocks_found = {}  # height -> (hash, workshares_included)
    workshares_total = set()  # All unique workshare hashes
    
    with open(log_file, 'rb') as f:
        content = f.read().decode('utf-8', errors='ignore')
        
        # Find all workshares added to pool (both mined and received)
        # Pattern: Added workshare <hash> to pool at position X (prev_id: <parent_hash>)
        workshare_pattern = r'Added workshare <([a-f0-9]{64})> to pool.*prev_id: <([a-f0-9]{64})>'
        for match in re.finditer(workshare_pattern, content):
            ws_hash = match.group(1)
            parent_hash = match.group(2)
            workshares_total.add(ws_hash)
            
            # Try to map parent hash to height (this is approximate)
            # We'll track by looking at found blocks
            
        # Find all blocks found with workshare counts
        # Pattern: Found block <hash> at height X for difficulty: Y, workshares included: Z
        block_pattern = r'Found block <([a-f0-9]{64})> at height (\d+).*workshares included: (\d+)'
        for match in re.finditer(block_pattern, content):
            block_hash = match.group(1)
            height = int(match.group(2))
            workshares_included = int(match.group(3))
            blocks_found[height] = (block_hash, workshares_included)
    
    return workshares_total, blocks_found

def get_block_workshares(height, rpc_port):
    """Get actual workshare hashes from a block via RPC"""
    cmd = [
        'curl', '-s', '-X', 'POST',
        f'http://127.0.0.1:{rpc_port}/json_rpc',
        '-d', json.dumps({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_block",
            "params": {"height": height}
        }),
        '-H', 'Content-Type: application/json'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        response = json.loads(result.stdout)
        if 'result' in response:
            block_data = json.loads(response['result'].get('json', '{}'))
            return block_data.get('workshare_hashes', [])
    except:
        pass
    
    return []

def analyze_efficiency():
    """Analyze workshare inclusion efficiency"""
    
    print("Analyzing workshare inclusion efficiency...")
    print("=" * 60)
    
    # Parse both node logs
    print("\nParsing NodeA log...")
    nodeA_workshares, nodeA_blocks = parse_logs('nodeA/testnet/bitmonero.log')
    
    print("Parsing NodeB log...")
    nodeB_workshares, nodeB_blocks = parse_logs('nodeB/testnet/bitmonero.log')
    
    # Combine all workshares (union of both nodes)
    all_workshares = nodeA_workshares.union(nodeB_workshares)
    print(f"\nTotal unique workshares produced by both nodes: {len(all_workshares)}")
    
    # Combine all blocks
    all_blocks = {}
    all_blocks.update(nodeA_blocks)
    all_blocks.update(nodeB_blocks)
    
    print(f"Total blocks mined: {len(all_blocks)}")
    
    # Track workshares actually included in blocks
    workshares_in_blocks = set()
    block_efficiencies = []
    workshares_available_per_block = {}
    
    # For each block, get the actual workshares included
    for height in sorted(all_blocks.keys()):
        block_hash, declared_count = all_blocks[height]
        
        # Try to get actual workshares from both RPC endpoints
        actual_workshares = get_block_workshares(height, 28081)
        if not actual_workshares:
            actual_workshares = get_block_workshares(height, 38081)
        
        if actual_workshares:
            workshares_in_blocks.update(actual_workshares)
            
            # Count how many workshares were available for this block
            # (This is approximate - we'd need to track by parent block properly)
            # For now, we'll calculate efficiency based on declared counts
            
    # Calculate overall efficiency
    total_workshares_declared = sum(count for _, count in all_blocks.values())
    
    print(f"\nTotal workshares declared in blocks: {total_workshares_declared}")
    print(f"Total unique workshares in blocks: {len(workshares_in_blocks)}")
    
    # Analyze per-block efficiency
    print("\n" + "=" * 60)
    print("PER-BLOCK ANALYSIS")
    print("=" * 60)
    
    # Get workshares per parent block
    parent_workshares = defaultdict(list)
    
    # Parse logs again to map workshares to parent blocks
    for log_file in ['nodeA/testnet/bitmonero.log', 'nodeB/testnet/bitmonero.log']:
        with open(log_file, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
            
            # Find workshares with their parent blocks
            pattern = r'Added workshare <([a-f0-9]{64})>.*prev_id: <([a-f0-9]{64})>'
            for match in re.finditer(pattern, content):
                ws_hash = match.group(1)
                parent_hash = match.group(2)
                parent_workshares[parent_hash].append(ws_hash)
    
    # Calculate efficiency for each block
    efficiencies = []
    efficiency_histogram = defaultdict(int)
    
    print(f"\n{'Height':<8} {'Included':<10} {'Available':<10} {'Efficiency':<12}")
    print("-" * 50)
    
    for height in sorted(all_blocks.keys())[-20:]:  # Last 20 blocks
        block_hash, included_count = all_blocks[height]
        
        # Get the parent hash for this block (height - 1)
        if height > 1:
            # Find parent block hash
            parent_blocks_at_height = []
            for h, (bhash, _) in all_blocks.items():
                if h == height - 1:
                    parent_blocks_at_height.append(bhash)
            
            # Count available workshares for any of these parent blocks
            available_count = 0
            for parent_hash in parent_blocks_at_height:
                available_count += len(parent_workshares.get(parent_hash, []))
            
            # Also check by searching logs for workshares at this height
            for log_file in ['nodeA/testnet/bitmonero.log', 'nodeB/testnet/bitmonero.log']:
                with open(log_file, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore')
                    # Count workshares found at this height
                    pattern = f'Found workshare at height {height-1}'
                    available_count += len(re.findall(pattern, content))
            
            if available_count > 0:
                efficiency = min(100.0, (included_count / available_count) * 100)
                efficiencies.append(efficiency)
                
                # Add to histogram (10% buckets)
                bucket = int(efficiency // 10) * 10
                efficiency_histogram[bucket] += 1
                
                print(f"{height:<8} {included_count:<10} {available_count:<10} {efficiency:<12.1f}%")
    
    # Print overall statistics
    print("\n" + "=" * 60)
    print("OVERALL STATISTICS")
    print("=" * 60)
    
    if efficiencies:
        print(f"Average inclusion efficiency: {np.mean(efficiencies):.1f}%")
        print(f"Median inclusion efficiency: {np.median(efficiencies):.1f}%")
        print(f"Min inclusion efficiency: {min(efficiencies):.1f}%")
        print(f"Max inclusion efficiency: {max(efficiencies):.1f}%")
    
    # Print histogram
    print("\n" + "=" * 60)
    print("EFFICIENCY HISTOGRAM (10% buckets)")
    print("=" * 60)
    
    for bucket in range(0, 101, 10):
        count = efficiency_histogram.get(bucket, 0)
        bar = '#' * count
        if bucket == 100:
            print(f"{bucket:3d}%     : {bar} ({count})")
        else:
            print(f"{bucket:3d}-{bucket+9:3d}%: {bar} ({count})")
    
    # Create matplotlib histogram if possible
    try:
        if efficiencies:
            plt.figure(figsize=(10, 6))
            plt.hist(efficiencies, bins=range(0, 110, 10), edgecolor='black')
            plt.xlabel('Inclusion Efficiency (%)')
            plt.ylabel('Number of Blocks')
            plt.title('Workshare Inclusion Efficiency Distribution')
            plt.xticks(range(0, 110, 10))
            plt.grid(True, alpha=0.3)
            plt.savefig('workshare_efficiency_histogram.png')
            print("\nHistogram saved to workshare_efficiency_histogram.png")
    except ImportError:
        print("\nNote: Install matplotlib to generate histogram plot")
    
    # Analyze workshare reuse
    print("\n" + "=" * 60)
    print("WORKSHARE REUSE ANALYSIS")
    print("=" * 60)
    
    # Count how many times workshares appear in blocks
    workshare_block_count = defaultdict(int)
    for height in all_blocks.keys():
        workshares = get_block_workshares(height, 28081)
        if not workshares:
            workshares = get_block_workshares(height, 38081)
        for ws in workshares:
            workshare_block_count[ws] += 1
    
    reuse_counts = list(workshare_block_count.values())
    if reuse_counts:
        unique_workshares = sum(1 for count in reuse_counts if count == 1)
        reused_workshares = sum(1 for count in reuse_counts if count > 1)
        print(f"Unique workshares (appear in 1 block): {unique_workshares}")
        print(f"Reused workshares (appear in >1 block): {reused_workshares}")
        if reused_workshares > 0:
            print(f"Max reuse: {max(reuse_counts)} times")
            print(f"Average appearances: {np.mean(reuse_counts):.2f}")

if __name__ == "__main__":
    analyze_efficiency()
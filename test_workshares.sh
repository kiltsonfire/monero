#!/bin/bash

# Kill any existing monerod processes
echo "Cleaning up old processes..."
pkill -9 -f monerod 2>/dev/null
sleep 5

# Clean up old test directories
echo "Cleaning up old test directories..."
rm -rf nodeA nodeB

# Create fresh directories
echo "Creating test directories..."
mkdir -p nodeA nodeB

# Start node A (seed node)
echo "Starting node A (seed)..."
./bin/monerod \
  --testnet \
  --data-dir ./nodeA \
  --p2p-bind-ip 127.0.0.1 --p2p-bind-port 28080 \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 28081 \
  --zmq-rpc-bind-ip 127.0.0.1 --zmq-rpc-bind-port 28082 \
  --no-igd --hide-my-port \
  --add-exclusive-node 127.0.0.1:38080 \
  --allow-local-ip \
  --fixed-difficulty 500 \
  --log-level 1 \
  --disable-dns-checkpoints \
  --check-updates disabled \
  --detach

echo "Waiting for node A to initialize..."
sleep 10

# Start node B (connects only to A)
echo "Starting node B (connects only to A)..."
./bin/monerod \
  --testnet \
  --data-dir ./nodeB \
  --p2p-bind-ip 127.0.0.1 --p2p-bind-port 38080 \
  --rpc-bind-ip 127.0.0.1 --rpc-bind-port 38081 \
  --zmq-rpc-bind-ip 127.0.0.1 --zmq-rpc-bind-port 38082 \
  --no-igd --hide-my-port \
  --add-exclusive-node 127.0.0.1:28080 \
  --allow-local-ip \
  --fixed-difficulty 500 \
  --log-level 1 \
  --disable-dns-checkpoints \
  --check-updates disabled \
  --detach

echo "Waiting for node B to initialize..."
sleep 15

# Wait for nodes to connect
echo "Waiting for nodes to connect..."
sleep 15

echo "Checking if nodes are ready..."
# Check both nodes are responding before starting mining
curl -s http://127.0.0.1:28081/get_height > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "Node A not responding, waiting more..."
  sleep 10
fi

curl -s http://127.0.0.1:38081/get_height > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "Node B not responding, waiting more..."
  sleep 10
fi

# Use the same testnet address for both miners (starts with 9)
# In production you'd use different addresses to track which miner found what
# But for testing workshare sharing, one address is fine
TESTNET_ADDRESS="9wq792k9sxVZiLn66S3Qzv8QfmtcwkdXgM5cWGsXAPxoQeMQ79md51PLPCijvzk1iHbuHi91pws5B7iajTX9KTtJ4bh2tCh"

echo "Both nodes will mine to: ${TESTNET_ADDRESS:0:20}..."
echo ""

# Start mining on node A
echo "Starting mining on node A..."
curl -X POST http://127.0.0.1:28081/start_mining \
  -H 'Content-Type: application/json' \
  -d "{
    \"miner_address\":\"$TESTNET_ADDRESS\",
    \"threads_count\":1,
    \"do_background_mining\":false,
    \"ignore_battery\":true
  }"

echo ""
echo "Waiting before starting second miner..."
sleep 5

# Start mining on node B
echo "Starting mining on node B..."
curl -X POST http://127.0.0.1:38081/start_mining \
  -H 'Content-Type: application/json' \
  -d "{
    \"miner_address\":\"$TESTNET_ADDRESS\",
    \"threads_count\":1,
    \"do_background_mining\":false,
    \"ignore_battery\":true
  }"

echo ""
echo "Test environment started!"
echo "Node A RPC: http://127.0.0.1:28081"
echo "Node B RPC: http://127.0.0.1:38081"
echo ""
echo "Monitor node A logs:"
echo "  tail -f nodeA/testnet/bitmonero.log | grep -E '(Found block|Found workshare|workshares|height)'"
echo ""
echo "Monitor node B logs:"
echo "  tail -f nodeB/testnet/bitmonero.log | grep -E '(Found block|Found workshare|workshares|height)'"
echo ""
echo "To see which node mined which blocks:"
echo "  grep 'Found block' nodeA/testnet/bitmonero.log | tail -5"
echo "  grep 'Found block' nodeB/testnet/bitmonero.log | tail -5"
echo ""
echo "Check heights:"
echo "  Node A: curl -s http://127.0.0.1:28081/get_height"
echo "  Node B: curl -s http://127.0.0.1:38081/get_height"
echo ""
echo "Check peer connections:"
echo "  Node A: curl -s http://127.0.0.1:28081/get_connections | jq '.connections | length'"
echo "  Node B: curl -s http://127.0.0.1:38081/get_connections | jq '.connections | length'"
echo ""
echo "To stop the test:"
echo "  pkill -f monerod"
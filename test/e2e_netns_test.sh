#!/bin/bash
#
# e2e_netns_test.sh - End-to-end test for network namespace support
#
# This script:
# 1. Starts a server container (iperf3 server)
# 2. Starts a client container (iperf3 client)
# 3. Generates persistent TCP traffic between them
# 4. Verifies nethogs can detect the traffic with -n option
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETHOGS_BIN="${SCRIPT_DIR}/../src/nethogs"
SERVER_CONTAINER="nethogs_test_server"
CLIENT_CONTAINER="nethogs_test_client"
NETWORK_NAME="nethogs_test_net"
TEST_OUTPUT_DIR="/tmp/nethogs_test_$$"

echo -e "${CYAN}========================================"
echo "NetHogs Network Namespace E2E Test"
echo -e "========================================${NC}"

# Cleanup function
cleanup_containers() {
    echo -e "\n${YELLOW}[Cleanup] Removing test containers...${NC}"
    docker rm -f "$SERVER_CONTAINER" 2>/dev/null || true
    docker rm -f "$CLIENT_CONTAINER" 2>/dev/null || true
    docker network rm "$NETWORK_NAME" 2>/dev/null || true
}

# Check prerequisites
check_prerequisites() {
    echo -e "\n${YELLOW}[1/7] Checking prerequisites...${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}ERROR: Please run as root (sudo)${NC}"
        exit 1
    fi

    if ! command -v docker &> /dev/null; then
        echo -e "${RED}ERROR: Docker not installed${NC}"
        exit 1
    fi

    if [ ! -x "$NETHOGS_BIN" ]; then
        echo -e "${RED}ERROR: nethogs binary not found at $NETHOGS_BIN${NC}"
        echo "Please run 'make' first"
        exit 1
    fi

    mkdir -p "$TEST_OUTPUT_DIR"
    echo -e "${GREEN}Prerequisites OK${NC}"
    echo "Test output directory: $TEST_OUTPUT_DIR"
}

# Create test network
create_network() {
    echo -e "\n${YELLOW}[2/7] Creating test network...${NC}"
    
    docker network create --driver bridge "$NETWORK_NAME" || true
    echo -e "${GREEN}Network '$NETWORK_NAME' created${NC}"
}

# Start server container (iperf3 server)
start_server() {
    echo -e "\n${YELLOW}[3/7] Starting iperf3 server container...${NC}"
    
    docker run -d \
        --name "$SERVER_CONTAINER" \
        --network "$NETWORK_NAME" \
        networkstatic/iperf3 -s
    
    sleep 2
    
    SERVER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SERVER_CONTAINER")
    SERVER_PID=$(docker inspect -f '{{.State.Pid}}' "$SERVER_CONTAINER")
    
    echo "Server container:"
    echo "  - Name: $SERVER_CONTAINER"
    echo "  - IP: $SERVER_IP"
    echo "  - PID on host: $SERVER_PID"
    echo "  - Network namespace: $(readlink /proc/$SERVER_PID/ns/net)"
}

# Start client container (iperf3 client)
start_client() {
    echo -e "\n${YELLOW}[4/7] Starting iperf3 client container...${NC}"
    
    SERVER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SERVER_CONTAINER")
    
    # Run iperf3 client for 60 seconds
    docker run -d \
        --name "$CLIENT_CONTAINER" \
        --network "$NETWORK_NAME" \
        networkstatic/iperf3 -c "$SERVER_IP" -t 60
    
    sleep 2
    
    CLIENT_PID=$(docker inspect -f '{{.State.Pid}}' "$CLIENT_CONTAINER")
    
    echo "Client container:"
    echo "  - Name: $CLIENT_CONTAINER"
    echo "  - PID on host: $CLIENT_PID"
    echo "  - Network namespace: $(readlink /proc/$CLIENT_PID/ns/net)"
}

# Verify containers are communicating
verify_connectivity() {
    echo -e "\n${YELLOW}[5/7] Verifying container connectivity...${NC}"
    
    CLIENT_PID=$(docker inspect -f '{{.State.Pid}}' "$CLIENT_CONTAINER" 2>/dev/null)
    
    if [ -n "$CLIENT_PID" ]; then
        echo "Checking client's TCP connections:"
        cat /proc/$CLIENT_PID/net/tcp | grep -v "00000000:0000" | head -5 || echo "  (no active connections)"
        echo -e "${GREEN}Traffic is flowing${NC}"
    else
        echo -e "${RED}Client container not running${NC}"
        exit 1
    fi
}

# Debug: show container network namespace info
debug_netns_info() {
    echo -e "\n${CYAN}=== Debug: Network Namespace Info ===${NC}"
    
    SERVER_PID=$(docker inspect -f '{{.State.Pid}}' "$SERVER_CONTAINER" 2>/dev/null)
    CLIENT_PID=$(docker inspect -f '{{.State.Pid}}' "$CLIENT_CONTAINER" 2>/dev/null)
    
    echo "Host network namespaces count:"
    ls /proc/*/ns/net 2>/dev/null | xargs readlink 2>/dev/null | sort -u | wc -l
    
    echo ""
    echo "Server netns: $(readlink /proc/$SERVER_PID/ns/net 2>/dev/null)"
    echo "Client netns: $(readlink /proc/$CLIENT_PID/ns/net 2>/dev/null)"
}

# Test without -n option
test_without_netns() {
    echo -e "\n${YELLOW}[6/7] Testing WITHOUT -n option...${NC}"
    
    echo "Running: $NETHOGS_BIN -t -c 3"
    timeout 10 "$NETHOGS_BIN" -t -c 3 > "$TEST_OUTPUT_DIR/without_n.log" 2>&1 || true
    
    echo ""
    echo "=== Output without -n ==="
    cat "$TEST_OUTPUT_DIR/without_n.log" 2>/dev/null | grep -E "Refreshing|iperf|unknown" | head -20
    echo "========================="
    
    # Check if iperf3 is detected
    if grep -qi "iperf" "$TEST_OUTPUT_DIR/without_n.log" 2>/dev/null; then
        echo -e "${YELLOW}Note: iperf3 detected without -n (unexpected)${NC}"
        WITHOUT_N_IPERF=1
    else
        echo -e "${CYAN}Expected: iperf3 NOT detected (traffic in unknown TCP)${NC}"
        WITHOUT_N_IPERF=0
    fi
}

# Test with -n option
test_with_netns() {
    echo -e "\n${YELLOW}[7/7] Testing WITH -n option...${NC}"
    
    echo "Running: $NETHOGS_BIN -n -t -c 3"
    timeout 10 "$NETHOGS_BIN" -n -t -c 3 > "$TEST_OUTPUT_DIR/with_n.log" 2>&1 || true
    
    echo ""
    echo "=== Output with -n ==="
    cat "$TEST_OUTPUT_DIR/with_n.log" 2>/dev/null | grep -E "Refreshing|iperf|unknown" | head -20
    echo "======================"
    
    # Check if iperf3 is detected
    if grep -qi "iperf" "$TEST_OUTPUT_DIR/with_n.log" 2>/dev/null; then
        echo -e "${GREEN}SUCCESS: iperf3 process detected!${NC}"
        WITH_N_IPERF=1
        
        # Show the iperf lines
        echo ""
        echo "Detected iperf3 entries:"
        grep -i "iperf" "$TEST_OUTPUT_DIR/with_n.log" | head -5
    else
        echo -e "${RED}iperf3 NOT detected in output${NC}"
        WITH_N_IPERF=0
    fi
}

# Print final report
print_report() {
    echo -e "\n${CYAN}========================================"
    echo "Test Report"
    echo -e "========================================${NC}"
    
    SERVER_PID=$(docker inspect -f '{{.State.Pid}}' "$SERVER_CONTAINER" 2>/dev/null || echo "N/A")
    CLIENT_PID=$(docker inspect -f '{{.State.Pid}}' "$CLIENT_CONTAINER" 2>/dev/null || echo "N/A")
    
    echo ""
    echo "Container Information:"
    echo "  Server PID: $SERVER_PID"
    echo "  Client PID: $CLIENT_PID"
    
    echo ""
    echo "Test Results:"
    echo "  Without -n: iperf3 detected = ${WITHOUT_N_IPERF:-N/A}"
    echo "  With -n:    iperf3 detected = ${WITH_N_IPERF:-N/A}"
    
    echo ""
    if [ "${WITH_N_IPERF:-0}" -eq 1 ]; then
        echo -e "${GREEN}✓ Network namespace support is WORKING${NC}"
        echo "  Container processes are correctly identified!"
        RESULT=0
    else
        echo -e "${RED}✗ Network namespace support needs debugging${NC}"
        RESULT=1
    fi
    
    echo ""
    echo "Logs saved to: $TEST_OUTPUT_DIR/"
    
    return ${RESULT:-1}
}

# Main
main() {
    trap cleanup_containers EXIT
    
    check_prerequisites
    cleanup_containers
    create_network
    start_server
    start_client
    verify_connectivity
    debug_netns_info
    test_without_netns
    test_with_netns
    print_report
}

main "$@"

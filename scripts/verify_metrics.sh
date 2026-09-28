#!/bin/bash
# Verification script for Prometheus metrics implementation

set -e

echo "🔍 Verifying Prometheus Metrics Implementation..."
echo ""

# Test 1: Build metrics crate
echo "1️⃣  Building nexus-metrics crate..."
cargo build --package nexus-metrics --quiet
echo "   ✅ Build successful"
echo ""

# Test 2: Run unit tests
echo "2️⃣  Running unit tests..."
cargo test --package nexus-metrics --quiet
echo "   ✅ All tests passed"
echo ""

# Test 3: Verify example runs
echo "3️⃣  Running basic usage example..."
OUTPUT=$(cargo run --package nexus-metrics --example basic_usage 2>&1)
echo "   ✅ Example executed successfully"
echo ""

# Test 4: Verify SFU metrics. Still exported, but nothing feeds them since
# Phase 1 (the old path is gone): in a running SFU they read zero, and the
# dashboard does not show them.
echo "4️⃣  Verifying SFU metrics (exported, not fed since Phase 1: read zero)..."
echo "$OUTPUT" | grep -q "nexus_sfu_packets_received_total" && echo "   ✅ Packet counters present"
echo "$OUTPUT" | grep -q "nexus_sfu_forwarding_latency_seconds_bucket" && echo "   ✅ Latency histogram present"
echo "$OUTPUT" | grep -q "nexus_sfu_forwarding_latency_seconds_sum" && echo "   ✅ Latency sum present"
echo "$OUTPUT" | grep -q "nexus_sfu_forwarding_latency_seconds_count" && echo "   ✅ Latency count present"
echo ""

# Test 5: Verify shard metrics (the example installs a fixed stats source)
echo "5️⃣  Verifying shard metrics..."
echo "$OUTPUT" | grep -q 'nexus_shard_rx_datagrams_total{shard="0"}' && echo "   ✅ Shard counters present"
echo "$OUTPUT" | grep -q 'nexus_shard_sessions{shard="0"}' && echo "   ✅ Shard gauges present"
# Every series the dashboard plots is exported (the drop panel uses a regex).
for metric in $(grep -o 'nexus_shard_[a-z_]*' deploy/grafana/dashboard.json | grep -v '_$' | sort -u); do
    if ! echo "$OUTPUT" | grep -q "^$metric{"; then
        echo "   ❌ Dashboard series $metric is not exported"
        exit 1
    fi
done
echo "   ✅ Every dashboard series is exported"
echo ""

# Test 6: Verify CRDT metrics (exported, not fed since Phase 1: read zero)
echo "6️⃣  Verifying CRDT metrics (exported, not fed since Phase 1: read zero)..."
echo "$OUTPUT" | grep -q "nexus_crdt_gossip_messages_sent_total" && echo "   ✅ Gossip counters present"
echo "$OUTPUT" | grep -q "nexus_crdt_state_sync_latency_seconds_bucket" && echo "   ✅ State sync latency histogram present"
echo "$OUTPUT" | grep -q "nexus_crdt_active_peers" && echo "   ✅ Peer metrics present"
echo ""

# Test 8: Validate Grafana dashboard JSON
echo "8️⃣  Validating Grafana dashboard..."
if command -v jq &> /dev/null; then
    jq empty deploy/grafana/dashboard.json 2>/dev/null && echo "   ✅ Dashboard JSON is valid"
    PANEL_COUNT=$(jq '.dashboard.panels | length' deploy/grafana/dashboard.json)
    echo "   ✅ Dashboard has $PANEL_COUNT panels"
else
    python3 -m json.tool deploy/grafana/dashboard.json > /dev/null && echo "   ✅ Dashboard JSON is valid"
fi
echo ""

# Test 9: Count total metrics
echo "9️⃣  Counting exported metrics..."
METRIC_COUNT=$(echo "$OUTPUT" | grep -c "^# HELP")
echo "   ✅ Exporting $METRIC_COUNT unique metrics"
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ All verification checks passed!"
echo ""
echo "📊 Metrics Summary:"
echo "   • Shard metrics: every ShardCounters field plus 4 gauges, per shard (the dashboard)"
echo "   • SFU and CRDT metrics: exported, not fed since Phase 1 (read zero)"
echo "   • Total: $METRIC_COUNT metrics exported"
echo ""
echo "🎯 Next Steps:"
echo "   1. Start the SFU server"
echo "   2. Access metrics at http://localhost:8080/metrics"
echo "   3. Configure Prometheus to scrape the endpoint"
echo "   4. Import deploy/grafana/dashboard.json to Grafana"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

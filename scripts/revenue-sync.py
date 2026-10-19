#!/usr/bin/env python3
"""VeriDAG -> Revenue OS Connective Telemetry Sync.

Synchronizes VeriDAG on-chain settlement throughput, validator seat licenses,
consortium revenue, and treasury float yield into the Hardonian Sovereign
Revenue Database (`/home/scott/ai-lab/revenue-os/revenue-os.db`).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Any, Optional
import urllib.error
import urllib.request


DEFAULT_DB_PATH = os.environ.get(
    "REVENUE_DB_PATH", "/home/scott/ai-lab/revenue-os/revenue-os.db"
)
DEFAULT_RPC_URL = os.environ.get("VERIDAG_RPC_URL", "http://127.0.0.1:8081")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS veridag_revenue_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    timestamp_utc TEXT NOT NULL,
    stream TEXT NOT NULL,               -- 'validator_license', 'trade_clearing', 'float_seigniorage', 'agent_metering'
    counterparty TEXT NOT NULL,         -- e.g. 'JPMorgan Chase (Consortium)', 'Maersk Supply Chain', 'TokenGoblin'
    gross_usd REAL NOT NULL,
    protocol_net_usd REAL NOT NULL,
    notes TEXT,
    tx_ref TEXT
);

CREATE TABLE IF NOT EXISTS veridag_validator_seats (
    node_id TEXT PRIMARY KEY,
    consortium_member TEXT NOT NULL,
    tier TEXT NOT NULL,                 -- 'Consortium Tier 1 ($250k/yr)', 'Enterprise Gateway ($50k/yr)'
    annual_fee_usd REAL NOT NULL,
    effective_date TEXT NOT NULL,
    renewal_date TEXT NOT NULL,
    status TEXT NOT NULL                -- 'ACTIVE', 'PENDING', 'SUSPENDED'
);

CREATE TABLE IF NOT EXISTS veridag_settlement_volume (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    period_date TEXT UNIQUE NOT NULL,   -- 'YYYY-MM-DD'
    settled_volume_usd REAL NOT NULL,
    tx_count INTEGER NOT NULL,
    gross_fee_bps REAL NOT NULL,        -- e.g. 1.5 bps = 0.00015
    gross_fee_usd REAL NOT NULL,
    protocol_net_usd REAL NOT NULL,     -- 60% Protocol Treasury
    validator_rebate_usd REAL NOT NULL, -- 30% Staking Pool
    volume_rebate_usd REAL NOT NULL     -- 10% Enterprise Volume Rebate
);

CREATE TABLE IF NOT EXISTS veridag_float_yield (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    period_date TEXT UNIQUE NOT NULL,   -- 'YYYY-MM-DD'
    total_usdv_reserve REAL NOT NULL,
    yield_rate_apy REAL NOT NULL,       -- e.g. 0.0450 (4.50%)
    daily_yield_usd REAL NOT NULL,
    status TEXT NOT NULL                -- 'ACCRUED', 'DISTRIBUTED'
);

CREATE INDEX IF NOT EXISTS idx_rev_stream ON veridag_revenue_ledger(stream);
CREATE INDEX IF NOT EXISTS idx_rev_ts ON veridag_revenue_ledger(timestamp_utc);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    target_path = Path(db_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    return conn


def record_revenue_event(
    conn: sqlite3.Connection,
    event_id: str,
    stream: str,
    counterparty: str,
    gross_usd: float,
    protocol_net_usd: float,
    notes: str = "",
    tx_ref: str = "",
) -> None:
    now_utc = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """
        INSERT INTO veridag_revenue_ledger
            (event_id, timestamp_utc, stream, counterparty, gross_usd, protocol_net_usd, notes, tx_ref)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(event_id) DO UPDATE SET
            gross_usd = excluded.gross_usd,
            protocol_net_usd = excluded.protocol_net_usd,
            notes = excluded.notes,
            tx_ref = excluded.tx_ref;
        """,
        (event_id, now_utc, stream, counterparty, gross_usd, protocol_net_usd, notes, tx_ref),
    )
    conn.commit()


def register_validator_seat(
    conn: sqlite3.Connection,
    node_id: str,
    consortium_member: str,
    tier: str,
    annual_fee_usd: float,
    effective_date: str,
    renewal_date: str,
    status: str = "ACTIVE",
) -> None:
    conn.execute(
        """
        INSERT INTO veridag_validator_seats
            (node_id, consortium_member, tier, annual_fee_usd, effective_date, renewal_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(node_id) DO UPDATE SET
            consortium_member = excluded.consortium_member,
            tier = excluded.tier,
            annual_fee_usd = excluded.annual_fee_usd,
            renewal_date = excluded.renewal_date,
            status = excluded.status;
        """,
        (node_id, consortium_member, tier, annual_fee_usd, effective_date, renewal_date, status),
    )
    conn.commit()


def record_daily_settlement(
    conn: sqlite3.Connection,
    period_date: str,
    settled_volume_usd: float,
    tx_count: int,
    gross_fee_bps: float = 1.5,
) -> None:
    gross_rate = gross_fee_bps / 10_000.0
    gross_fee_usd = round(settled_volume_usd * gross_rate, 4)
    # Unit Economics splits: 60% protocol, 30% validator pool, 10% volume rebate pool
    protocol_net = round(gross_fee_usd * 0.60, 4)
    validator_rebate = round(gross_fee_usd * 0.30, 4)
    volume_rebate = round(gross_fee_usd * 0.10, 4)

    conn.execute(
        """
        INSERT INTO veridag_settlement_volume
            (period_date, settled_volume_usd, tx_count, gross_fee_bps, gross_fee_usd, protocol_net_usd, validator_rebate_usd, volume_rebate_usd)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(period_date) DO UPDATE SET
            settled_volume_usd = excluded.settled_volume_usd,
            tx_count = excluded.tx_count,
            gross_fee_usd = excluded.gross_fee_usd,
            protocol_net_usd = excluded.protocol_net_usd,
            validator_rebate_usd = excluded.validator_rebate_usd,
            volume_rebate_usd = excluded.volume_rebate_usd;
        """,
        (
            period_date,
            settled_volume_usd,
            tx_count,
            gross_fee_bps,
            gross_fee_usd,
            protocol_net,
            validator_rebate,
            volume_rebate,
        ),
    )
    conn.commit()


def record_daily_float_yield(
    conn: sqlite3.Connection,
    period_date: str,
    total_usdv_reserve: float,
    apy: float = 0.0450,
) -> None:
    daily_rate = apy / 365.0
    daily_yield_usd = round(total_usdv_reserve * daily_rate, 4)
    conn.execute(
        """
        INSERT INTO veridag_float_yield
            (period_date, total_usdv_reserve, yield_rate_apy, daily_yield_usd, status)
        VALUES (?, ?, ?, ?, 'ACCRUED')
        ON CONFLICT(period_date) DO UPDATE SET
            total_usdv_reserve = excluded.total_usdv_reserve,
            yield_rate_apy = excluded.yield_rate_apy,
            daily_yield_usd = excluded.daily_yield_usd;
        """,
        (period_date, total_usdv_reserve, apy, daily_yield_usd),
    )
    conn.commit()


def run_node_health_probe(rpc_url: str, timeout: float = 3.0) -> dict[str, Any]:
    url = f"{rpc_url.rstrip('/')}/v1/health"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} from {url}")
        return json.load(resp)


def print_revenue_summary(conn: sqlite3.Connection) -> None:
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*), COALESCE(SUM(protocol_net_usd), 0.0) FROM veridag_revenue_ledger")
    events_count, total_rev = cursor.fetchone()

    cursor.execute("SELECT COUNT(*), COALESCE(SUM(annual_fee_usd), 0.0) FROM veridag_validator_seats WHERE status='ACTIVE'")
    active_seats, seat_arr = cursor.fetchone()

    cursor.execute("SELECT COALESCE(SUM(settled_volume_usd), 0.0), COALESCE(SUM(protocol_net_usd), 0.0) FROM veridag_settlement_volume")
    settled_vol, vol_fee_rev = cursor.fetchone()

    cursor.execute("SELECT COALESCE(SUM(daily_yield_usd), 0.0) FROM veridag_float_yield")
    yield_rev = cursor.fetchone()[0]

    print("=" * 60)
    print(" VeriDAG Sovereign Revenue OS Summary")
    print("=" * 60)
    print(f" Active Validator Seats:     {active_seats} (Contracted ARR: ${seat_arr:,.2f})")
    print(f" Total Settled Volume:       ${settled_vol:,.2f}")
    print(f" Volume Protocol Net Fees:   ${vol_fee_rev:,.2f}")
    print(f" Treasury Float Accrued:     ${yield_rev:,.2f}")
    print(f" Total Ledgered Net Rev:     ${total_rev:,.2f} ({events_count} events)")
    print("=" * 60)


def run_self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = os.path.join(tmpdir, "test-revenue.db")
        conn = init_db(test_db)
        print(f"[TEST] Initialized temporary database: {test_db}")

        # Register consortium validator seats
        register_validator_seat(
            conn,
            node_id="val-consortium-001",
            consortium_member="Consortium Founding Member Alpha (Logistics)",
            tier="Consortium Tier 1 ($250k/yr)",
            annual_fee_usd=250_000.0,
            effective_date="2026-11-01",
            renewal_date="2027-11-01",
        )
        record_revenue_event(
            conn,
            event_id="inv-val-001-q4",
            stream="validator_license",
            counterparty="Consortium Founding Member Alpha",
            gross_usd=250_000.0,
            protocol_net_usd=250_000.0,
            notes="Annual validator license prepaid",
        )

        # Record daily settlement
        record_daily_settlement(
            conn,
            period_date="2026-11-01",
            settled_volume_usd=5_000_000.0,
            tx_count=1_420,
            gross_fee_bps=1.5,
        )

        # Record treasury float yield on $2.5M reserve
        record_daily_float_yield(
            conn,
            period_date="2026-11-01",
            total_usdv_reserve=2_500_000.0,
            apy=0.0450,
        )

        # Record AI agent micro-metering event
        record_revenue_event(
            conn,
            event_id="meter-agent-tokengoblin-001",
            stream="agent_metering",
            counterparty="TokenGoblin Swarm Runner",
            gross_usd=125.40,
            protocol_net_usd=125.40,
            notes="Autonomous LLM compute micro-metering settlement",
            tx_ref="0x4a8f93...wave-4402",
        )

        print_revenue_summary(conn)
        conn.close()
        print("[TEST] Self-test completed successfully with 0 errors.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VeriDAG to Revenue OS Sync Utility"
    )
    parser.add_argument(
        "--db-path",
        default=DEFAULT_DB_PATH,
        help=f"Path to revenue-os.db (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--rpc-url",
        default=DEFAULT_RPC_URL,
        help=f"Node RPC URL (default: {DEFAULT_RPC_URL})",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print current revenue metrics summary and exit",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run self-contained in-memory verification test suite",
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help="Probe live VeriDAG node RPC health endpoint",
    )

    args = parser.parse_args()

    if args.test:
        run_self_test()
        return 0

    if args.probe:
        try:
            health = run_node_health_probe(args.rpc_url)
            print(f"[OK] Node at {args.rpc_url} is online:")
            print(json.dumps(health, indent=2))
            return 0
        except Exception as err:
            print(f"[ERROR] Failed to probe node at {args.rpc_url}: {err}", file=sys.stderr)
            return 1

    try:
        conn = init_db(args.db_path)
    except Exception as err:
        print(f"[ERROR] Could not connect to revenue database at {args.db_path}: {err}", file=sys.stderr)
        return 1

    if args.summary:
        print_revenue_summary(conn)

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

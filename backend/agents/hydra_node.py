"""
=============================================================================
Sentinel Orchestrator Network (SON) - HYDRA HEAD SIMULATION
=============================================================================

Role: Off-chain L2 State Channel for ultra-fast security checks.
Performance: < 0.2 seconds per check.

Simulates a Hydra Head that runs validation logic off-chain.
"""

import logging
import asyncio
from typing import Dict, Any
from datetime import datetime
from .hydra_client import HydraClient

logger = logging.getLogger(__name__)

class HydraNode:
    """
    Interface to a real Hydra Head Node.
    """

    def __init__(self, head_id: str = "hydra-head-01"):
        self.head_id = head_id
        self.client = HydraClient(host="localhost", port=4001)
        self.is_connected = False
        self.is_open = True
        self.participants = ["sentinel_node", "oracle_node", "user_node"]
        self.snapshot_utxo = {}  # Mock UTXO set
        
    async def validate_transaction_offchain(self, tx_cbor: str, policy_id: str) -> Dict[str, Any]:
        """
        Validate a transaction using the real Hydra Node.
        """
        try:
            timestamp = datetime.utcnow().isoformat()

            # Connect if not already connected
            if not self.is_connected:
                try:
                    await self.client.connect()
                    self.is_connected = True
                except Exception as e:
                    logger.error(f"❌ Could not connect to Hydra Node: {e}")
                    return {
                        "verified": False,
                        "verdict": "UNKNOWN",
                        "reason": "Hydra Node Offline - Real validation required",
                        "latency_ms": 0,
                        "head_id": self.head_id,
                        "timestamp": timestamp
                    }

            # 1. Local Policy Check (Fast Fail)
            # We must keep this for the demo to work with "deadbeef" patterns,
            # as the real Hydra node won't know about these specific demo threats.
            if policy_id and policy_id.lower().startswith(("dead", "scam", "fake")):
                return {
                    "verified": True,
                    "verdict": "DANGER",
                    "risk_score": 100,
                    "reason": "Hydra: Policy ID matches known malicious pattern (Blacklist)",
                    "latency_ms": 5,
                    "head_id": self.head_id,
                    "timestamp": timestamp
                }

            # 2. Real Hydra Validation (if we have CBOR)
            # If we only have policy_id, we can't validate against Hydra ledger without a transaction.
            # For this demo, if we don't have CBOR, we'll assume SAFE if it passed the local check.
            
            if not tx_cbor or len(tx_cbor) < 10:
                 return {
                    "verified": False,
                    "verdict": "UNKNOWN",
                    "risk_score": 0,
                    "reason": "Hydra: No TX CBOR - deferring to Oracle for on-chain check",
                    "latency_ms": 0,
                    "head_id": self.head_id,
                    "timestamp": timestamp
                }

            # 3. Submit to Hydra Node
            start_time = datetime.now()
            result = await self.client.validate_tx(tx_cbor)
            latency = (datetime.now() - start_time).total_seconds() * 1000
            
            if result["valid"]:
                return {
                    "verified": True,
                    "verdict": "SAFE",
                    "risk_score": 0,
                    "reason": f"Hydra: Validated by Head (TxID: {result.get('tx_id')})",
                    "latency_ms": int(latency),
                    "head_id": self.head_id,
                    "timestamp": timestamp
                }
            else:
                 return {
                    "verified": True,
                    "verdict": "DANGER", # Or UNSAFE
                    "risk_score": 80,
                    "reason": f"Hydra: Validation Failed - {result.get('reason')}",
                    "latency_ms": int(latency),
                    "head_id": self.head_id,
                    "timestamp": timestamp
                }

        except Exception as e:
            logger.error(f"Hydra validation error: {e}")
            return {
                "verified": False,
                "verdict": "UNKNOWN",
                "reason": f"Hydra Node Error: {str(e)}",
                "latency_ms": 0
            }

    async def init_head(self):
        """Simulate Head initialization."""
        await asyncio.sleep(0.5)
        self.is_open = True
        return True

    async def close_head(self):
        """Simulate Head closure."""
        await asyncio.sleep(0.5)
        self.is_open = False
        return True

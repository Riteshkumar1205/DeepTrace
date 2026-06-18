import hashlib
import random
from typing import Optional, Dict, Any
from sqlmodel import Session, select
from app.models.schemas import BlockchainRecord, Evidence, Hashes, AuditLog
from app.utils.time import utc_now

class BlockchainService:
    @staticmethod
    def register_evidence(db: Session, evidence_id: str, actor_email: str) -> Optional[BlockchainRecord]:
        """
        Registers an evidence item on the simulated blockchain ledger.
        Generates transaction receipts, block numbers, and owner certificates.
        Adds audit logs to track this transaction in the Chain of Custody.
        """
        # 1. Check if evidence exists
        evidence = db.exec(select(Evidence).where(Evidence.id == evidence_id)).first()
        if not evidence:
            return None

        # 2. Check if already registered
        existing_record = db.exec(select(BlockchainRecord).where(BlockchainRecord.evidence_id == evidence_id)).first()
        if existing_record:
            return existing_record

        # Get evidence hash
        hashes_rec = db.exec(select(Hashes).where(Hashes.evidence_id == evidence_id)).first()
        sha256_val = hashes_rec.sha256 if hashes_rec else "unknown"

        # 3. Simulate Transaction Anchor
        chain_name = "Polygon PoS (Mainnet Anchor)"
        
        # Deterministic but simulated transaction hash
        txn_raw = f"anchor-deeptrace-{evidence_id}-{sha256_val}-{utc_now().isoformat()}"
        transaction_hash = "0x" + hashlib.sha256(txn_raw.encode()).hexdigest()
        
        # Simulate block confirmations (random high-number height)
        block_number = random.randint(45800000, 45900000)
        
        # Generate an owner wallet/certificate signature from actor email
        registered_owner = "0x" + hashlib.sha256(actor_email.encode()).hexdigest()[:40]

        # 4. Save to Database
        blockchain_rec = BlockchainRecord(
            evidence_id=evidence_id,
            chain_name=chain_name,
            transaction_hash=transaction_hash,
            block_number=block_number,
            registered_owner=registered_owner,
            verification_status="VERIFIED OWNER"
        )
        db.add(blockchain_rec)

        # Log to Chain of Custody (AuditLog)
        audit_log = AuditLog(
            evidence_id=evidence_id,
            actor=actor_email,
            operation="Blockchain Ledger Anchor",
            hash_value=sha256_val,
            result=f"Success - Block #{block_number} Confirmed"
        )
        db.add(audit_log)
        db.commit()
        db.refresh(blockchain_rec)

        return blockchain_rec

    @staticmethod
    def verify_ledger_record(db: Session, evidence_id: str) -> Dict[str, Any]:
        """
        Queries and verifies the blockchain receipt for an evidence item.
        """
        record = db.exec(select(BlockchainRecord).where(BlockchainRecord.evidence_id == evidence_id)).first()
        if not record:
            return {
                "verified": False,
                "verification_status": "UNREGISTERED",
                "message": "No transaction anchors found on any registered ledger."
            }

        return {
            "verified": True,
            "verification_status": record.verification_status,
            "chain_name": record.chain_name,
            "transaction_hash": record.transaction_hash,
            "block_number": record.block_number,
            "registered_owner": record.registered_owner,
            "timestamp": record.created_at.isoformat()
        }

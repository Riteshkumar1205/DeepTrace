from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from sqlmodel import Session, select

from app.models.schemas import EventLog


class EventService:
    @staticmethod
    def log(
        db: Session,
        *,
        event_type: str,
        message: str,
        severity: str = "INFO",
        source: str = "backend",
        user_email: Optional[str] = None,
        session_id: Optional[str] = None,
        case_id: Optional[int] = None,
        evidence_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> EventLog:
        record = EventLog(
            severity=severity.upper(),
            event_type=event_type,
            message=message,
            source=source,
            user_email=user_email,
            session_id=session_id,
            case_id=case_id,
            evidence_id=evidence_id,
            payload=payload or {},
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def recent(db: Session, since_id: Optional[int] = None, limit: int = 250) -> list[EventLog]:
        query = select(EventLog).order_by(EventLog.id.desc()).limit(limit)
        if since_id is not None:
            query = select(EventLog).where(EventLog.id > since_id).order_by(EventLog.id.asc())
        return list(db.exec(query).all())

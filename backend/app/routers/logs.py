# app/routers/logs.py
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict
import math, re
from typing import List, Dict, Any, Optional

from app.database import get_db
from app import models
from app.deps import current_user

router = APIRouter(prefix="/logs", tags=["logs"])

STOPWORDS = {
    "the","a","an","to","and","or","of","for","on","at","in","by","with","from",
    "is","are","was","were","be","been","it","this","that","as","via","ua","curl"
}

_reason_re = re.compile(r"([a-z_]+)")
_token_re  = re.compile(r"[A-Za-z0-9\.\-\_]+")

def _extract_reason_tokens(reason_raw: str) -> List[str]:
    toks: List[str] = []
    for piece in (reason_raw or "").split("|"):
        m = _reason_re.search(piece)
        if m:
            toks.append(m.group(1))
    return toks

def _tokenize(text: str) -> List[str]:
    if not text:
        return []
    toks = [t.lower() for t in _token_re.findall(text)]
    return [t for t in toks if t not in STOPWORDS and not t.isdigit() and len(t) > 1]

def _short_hash(h: str) -> str:
    return (h[:10] + "…") if h and len(h) > 12 else h

def _window_events_db(db: Session, user_id: int, hours: int) -> List[Dict[str, Any]]:
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    rows = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == user_id, models.LoginEvent.ts >= cutoff)
        .order_by(models.LoginEvent.ts.asc())
        .all()
    )
    out: List[Dict[str, Any]] = []
    for r in rows:
        ts = r.ts
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        out.append({
            "_ts_dt": ts,
            "ip": r.ip,
            "ua": r.user_agent,
            "device": r.device_hash,
            "reason": r.risk_reason,
        })
    return out

# /logs/keyphrases
class Keyphrase(BaseModel):
    term: str
    score: float

class KeyphraseOut(BaseModel):
    window_hours: int
    keyphrases: List[Keyphrase]
    narrative: str

@router.get("/keyphrases", response_model=KeyphraseOut)
def keyphrases(
    hours: int = Query(24, ge=1, le=24*30),
    k: int = Query(8, ge=1, le=25),
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    evs = _window_events_db(db, u.id, hours)
    if not evs:
        return KeyphraseOut(window_hours=hours, keyphrases=[], narrative=f"No login events in the last {hours}h.")

    docs: List[List[str]] = []
    for e in evs:
        parts: List[str] = []
        parts += _extract_reason_tokens(e.get("reason", ""))
        parts += _tokenize(e.get("ua", ""))                   # user-agent
        parts += _tokenize(_short_hash(e.get("device", "")))  # short device hash
        docs.append(parts)

    N = len(docs)
    df = Counter()
    for d in docs:
        df.update(set(d))

    scores = Counter()
    for d in docs:
        tf = Counter(d)
        for term, freq in tf.items():
            idf = math.log((N + 1) / (1 + df[term])) + 1.0
            scores[term] += (freq * idf)

    top = [Keyphrase(term=t, score=round(s, 3)) for t, s in scores.most_common(k)]
    top_terms = ", ".join(t.term for t in top) or "—"
    narrative = f"Top phrases over last {hours}h: {top_terms}."
    return KeyphraseOut(window_hours=hours, keyphrases=top, narrative=narrative)

# /logs/topics
class Topic(BaseModel):
    label: str
    size: int
    sample_ts: datetime

class TopicsOut(BaseModel):
    window_hours: int
    topics: List[Topic]
    narrative: str

@router.get("/topics", response_model=TopicsOut)
def topics(
    hours: int = Query(168, ge=1, le=24*30),
    k: int = Query(5, ge=1, le=20),
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    evs = _window_events_db(db, u.id, hours)
    if not evs:
        return TopicsOut(window_hours=hours, topics=[], narrative=f"No login events in the last {hours}h.")

    def ua_family(ua: str) -> str:
        if not ua: return "ua:unknown"
        ua = ua.lower()
        if "iphone" in ua: return "ua:iphone"
        if "android" in ua: return "ua:android"
        if "curl" in ua: return "ua:curl"
        if "windows" in ua: return "ua:windows"
        if "mac" in ua or "darwin" in ua: return "ua:mac"
        return "ua:other"

    buckets: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    for e in evs:
        reasons = tuple(sorted(set(_extract_reason_tokens(e.get("reason","")))))
        dev = _short_hash(e.get("device"))
        uaf = ua_family(e.get("ua",""))
        key = (reasons, dev, uaf)
        buckets[key].append(e)

    items = sorted(buckets.items(), key=lambda kv: len(kv[1]), reverse=True)[:k]
    out: List[Topic] = []
    labels: List[str] = []
    for (reasons, dev, uaf), rows in items:
        size = len(rows)
        sample_ts = max(r["_ts_dt"] for r in rows)
        label_bits: List[str] = []
        if reasons: label_bits.append("/".join(reasons))
        if dev:     label_bits.append(dev)
        if uaf:     label_bits.append(uaf)
        label = " | ".join(label_bits) or "misc"
        out.append(Topic(label=label, size=size, sample_ts=sample_ts))
        labels.append(f"{label}({size})")

    narrative = f"Top {len(out)} login themes over last {hours}h: " + ", ".join(labels) + "."
    return TopicsOut(window_hours=hours, topics=out, narrative=narrative)

# /logs/diff
class DiffOut(BaseModel):
    hours: int
    vs_hours: int
    current_total: int
    prev_total: int
    delta_total: int
    top_increases: List[Dict[str, Any]]
    narrative: str

@router.get("/diff", response_model=DiffOut)
def diff(
    hours: int = Query(24, ge=1, le=24*30),
    vs_hours: Optional[int] = Query(None, ge=1, le=24*30),
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    if vs_hours is None:
        vs_hours = hours
    now = datetime.utcnow()

    cur_evs = _window_events_db(db, u.id, hours)

    prev_cut = now - timedelta(hours=hours + vs_hours)
    prev_end = now - timedelta(hours=hours)
    prev_rows = (
        db.query(models.LoginEvent)
        .filter(
            models.LoginEvent.user_id == u.id,
            models.LoginEvent.ts >= prev_cut,
            models.LoginEvent.ts < prev_end,
        )
        .order_by(models.LoginEvent.ts.asc())
        .all()
    )
    prev_evs = [{"_ts_dt": (r.ts if r.ts.tzinfo else r.ts.replace(tzinfo=timezone.utc)),
                 "ip": r.ip, "ua": r.user_agent, "device": r.device_hash, "reason": r.risk_reason}
                for r in prev_rows]

    def reason_counts(rows: List[Dict[str, Any]]) -> Counter:
        c = Counter()
        for e in rows:
            for r in _extract_reason_tokens(e.get("reason","")):
                c[r] += 1
        return c

    cur_total = len(cur_evs)
    prev_total = len(prev_evs)
    delta_total = cur_total - prev_total

    cur_rc = reason_counts(cur_evs)
    prev_rc = reason_counts(prev_evs)

    inc: List[Dict[str, Any]] = []
    all_keys = set(cur_rc) | set(prev_rc)
    for k in all_keys:
        d = cur_rc.get(k, 0) - prev_rc.get(k, 0)
        if d > 0:
            inc.append({"reason": k, "delta": d, "current": cur_rc.get(k,0), "prev": prev_rc.get(k,0)})
    inc.sort(key=lambda x: x["delta"], reverse=True)

    sign = "+" if delta_total >= 0 else ""
    if cur_total == prev_total == 0:
        narrative = f"No login activity in either window (last {hours}h vs prior {vs_hours}h)."
    else:
        top_bits = ", ".join(f"{i['reason']}({i['delta']:+d})" for i in inc[:3]) or "—"
        narrative = f"Logins: {cur_total} vs {prev_total} ({sign}{delta_total}). Top reason increases: {top_bits}."

    return DiffOut(
        hours=hours,
        vs_hours=vs_hours,
        current_total=cur_total,
        prev_total=prev_total,
        delta_total=delta_total,
        top_increases=inc[:5],
        narrative=narrative
    )

class SummaryOut(BaseModel):
    counts: Dict[str, int]
    narrative: str

@router.get("/summary", response_model=SummaryOut)
def summary(
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    # Count this user's login events (extend later if you want)
    total = (
        db.query(models.LoginEvent)
        .filter(models.LoginEvent.user_id == u.id)
        .count()
    )
    return SummaryOut(
        counts={"total": int(total)},
        narrative=f"Summary for user {u.id}: {total} login events."
    )

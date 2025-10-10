# app/routers/recs.py
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import date, datetime, timedelta
from typing import List, Dict, Any, Optional, Literal, Tuple
import math, random

from app.database import get_db
from app import models
from app.deps import current_user

router = APIRouter(prefix="/recs", tags=["recs"])

# helpers
def _month_bounds(month: Optional[str]) -> Tuple[date, date, str]:
    """month='YYYY-MM' -> (start_date, end_date_exclusive, 'YYYY-MM')"""
    if month:
        y, m = [int(x) for x in month.split("-")]
    else:
        today = date.today()
        y, m = today.year, today.month
    start = date(y, m, 1)
    end = date(y + 1, 1, 1) if m == 12 else date(y, m + 1, 1)
    return start, end, f"{y:04d}-{m:02d}"

def _round_up(x: float, base: float = 50.0) -> float:
    return float(int(math.ceil(x / base)) * base)

def _laplace(scale: float) -> float:
    """Sample Laplace(0, b=scale) without numpy."""
    if scale <= 0:
        return 0.0
    # difference of two iid exponential(1/scale)
    return random.expovariate(1.0/scale) - random.expovariate(1.0/scale)

def _safe(val: Optional[float]) -> float:
    return float(val or 0.0)

# schemas
class RecTip(BaseModel):
    id: str
    kind: Literal["budget","savings","goal","generic"]
    title: str
    body: str
    score: int = 50         # ordering priority (higher first)
    data: Dict[str, Any] = Field(default_factory=dict)

class RecsOut(BaseModel):
    month: str
    dp: bool
    epsilon: Optional[float] = None
    tips: List[RecTip]
    metrics: Dict[str, Any]
    narrative: str

# endpoint
@router.get("/spend", response_model=RecsOut)
def spend_recommendations(
    month: Optional[str] = Query(None, description="YYYY-MM (defaults to current month)"),
    dp: bool = Query(False, description="Apply Laplace noise to numeric metrics"),
    epsilon: float = Query(1.0, ge=0.01, le=10.0, description="DP epsilon (lower = more noise)"),
    max_tips: int = Query(3, ge=1, le=10),
    db: Session = Depends(get_db),
    u: models.User = Depends(current_user),
):
    """
    Privacy-aware personal spend nudges. Uses *only* the caller’s own data.
    If dp=true, adds Laplace noise to the shown aggregates (experimental).
    """
    start, end, month_str = _month_bounds(month)

    # pulling this user's month data
    # totals by category
    rows = (
        db.query(models.Transaction.category, func.sum(models.Transaction.amount).label("amt"))
        .filter(
            models.Transaction.user_id == u.id,
            models.Transaction.date >= start,
            models.Transaction.date < end,
        )
        .group_by(models.Transaction.category)
        .all()
    )
    total_by_cat = { (c or "UNCAT"): float(a or 0.0) for (c, a) in rows }
    total_spent = sum(total_by_cat.values())

    # budgets for the month
    budgets = (
        db.query(models.Budget.category, models.Budget.amount)
        .filter(
            models.Budget.user_id == u.id,
            models.Budget.month == start.month,
            models.Budget.year == start.year,
        )
        .all()
    )
    budget_map = { (c or "UNCAT"): float(a or 0.0) for (c, a) in budgets }

    # first active goal (if any)
    goal = (
        db.query(models.Goal)
        .filter(models.Goal.user_id == u.id)
        .order_by(models.Goal.created_at.asc())
        .first()
    )

    # optional DP noise (Laplace)
    metrics: Dict[str, Any] = {
        "month": month_str,
        "total_spent": total_spent,
        "by_category": total_by_cat.copy(),
    }
    if dp:
        # naive sensitivity choices for demo purposes:
        sens_total = 100.0     # assume single-month contribution bounded
        sens_cat   = 75.0
        b_total = sens_total / max(epsilon, 1e-6)
        b_cat   = sens_cat   / max(epsilon, 1e-6)
        noisy_total = max(0.0, total_spent + _laplace(b_total))
        noisy_by_cat = {k: max(0.0, v + _laplace(b_cat)) for k, v in total_by_cat.items()}
        metrics.update({
            "dp": True,
            "epsilon": epsilon,
            "noisy_total_spent": float(round(noisy_total, 2)),
            "noisy_by_category": {k: float(round(v, 2)) for k, v in noisy_by_cat.items()},
        })
        # Use the noisy values for tip computations (so messages match shown numbers)
        total_by_cat = noisy_by_cat
        total_spent = noisy_total
    else:
        metrics["dp"] = False

    tips: List[RecTip] = []

    # Tip A: Budget progress / overspend
    for cat, spent in sorted(total_by_cat.items(), key=lambda kv: kv[1], reverse=True):
        if cat in budget_map and budget_map[cat] > 0:
            b = budget_map[cat]
            ratio = spent / b
            pct = int(round(ratio * 100))
            if ratio >= 1.0:
                tips.append(RecTip(
                    id=f"overspend-{cat.lower()}",
                    kind="budget",
                    title=f"Overspent {cat} budget",
                    body=f"You’re at ~{pct}% of your {cat} budget for {month_str}. Consider pausing non-essentials in this category or raising next month’s budget.",
                    score=90,
                    data={"category": cat, "spent": round(spent,2), "budget": b, "progress_pct": pct},
                ))
            elif ratio >= 0.8:
                tips.append(RecTip(
                    id=f"near-limit-{cat.lower()}",
                    kind="budget",
                    title=f"Close to {cat} budget limit",
                    body=f"You’ve used ~{pct}% of your {cat} budget. Set an alert or small cap for the rest of {month_str}.",
                    score=75,
                    data={"category": cat, "spent": round(spent,2), "budget": b, "progress_pct": pct},
                ))
        else:
            # No budget set
            if spent >= 200:  # simple threshold to avoid tiny categories
                suggested = _round_up(spent * 1.10, base=50.0)
                tips.append(RecTip(
                    id=f"suggest-budget-{cat.lower()}",
                    kind="budget",
                    title=f"Set a {cat} budget",
                    body=f"You spent about {round(spent,2)} in {cat} this month. A starter budget for next month could be ~{int(suggested)}.",
                    score=60,
                    data={"category": cat, "suggested_budget": suggested, "observed_spend": round(spent,2)},
                ))

    # Round-up savings estimate (micro-savings)
    # sum of (ceil(amount) - amount) for all tx this month if we rounded to the next unit
    txs = (
        db.query(models.Transaction.amount)
        .filter(
            models.Transaction.user_id == u.id,
            models.Transaction.date >= start,
            models.Transaction.date < end,
        ).all()
    )
    roundups = sum((math.ceil(float(a)) - float(a)) % 1.0 for (a,) in txs)
    if dp:
        roundups = max(0.0, roundups + _laplace(5.0 / max(epsilon,1e-6)))  # toy sensitivity
    if roundups >= 5.0:
        tips.append(RecTip(
            id="roundup-savings",
            kind="savings",
            title="Turn on round-up savings",
            body=f"If you rounded each purchase to the next whole unit, you’d have saved ~{round(roundups,2)} this month. Consider auto-sweeping round-ups into savings.",
            score=55,
            data={"estimated_roundups": round(roundups,2)},
        ))

    # Goal backplan (if a goal exists)
    if goal and goal.target_amount and goal.target_date:
        remain = max(0.0, float(goal.target_amount) - float(goal.current_amount or 0.0))
        days_left = (goal.target_date - date.today()).days
        if days_left > 7 and remain > 0:
            weekly = remain / (days_left / 7.0)
            if dp:
                weekly = max(0.0, weekly + _laplace(20.0 / max(epsilon,1e-6)))  # toy sensitivity
            tips.append(RecTip(
                id="goal-backplan",
                kind="goal",
                title=f"Track to “{goal.name}”",
                body=f"To hit **{goal.name}** by {goal.target_date}, set an auto-contribution of ~{int(round(weekly/4.0))}/week or {int(round(weekly))}/month.",
                score=70,
                data={
                    "goal_id": goal.id,
                    "remaining": round(remain,2),
                    "days_left": days_left,
                    "suggest_weekly": round(weekly,2),
                },
            ))

    # order & trim
    tips.sort(key=lambda t: t.score, reverse=True)
    tips = tips[:max_tips]

    # short narrative
    bits = []
    for t in tips:
        if t.kind == "budget" and "category" in t.data:
            bits.append(f"{t.data['category']}")
        elif t.kind == "goal":
            bits.append("goal")
        elif t.kind == "savings":
            bits.append("round-ups")
    narrative = (
        f"Privacy-aware suggestions for {month_str}: " +
        (", ".join(bits) if bits else "no strong nudges right now") + "."
    )

    return RecsOut(
        month=month_str,
        dp=dp,
        epsilon=epsilon if dp else None,
        tips=tips,
        metrics=metrics,
        narrative=narrative,
    )

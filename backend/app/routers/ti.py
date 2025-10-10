# app/routers/ti.py
from __future__ import annotations
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Dict, Any
from app.deps import current_user
from app import models
from app.threat_intel import status as ti_status, reload as ti_reload, lookup_ip, check_email_domain

router = APIRouter(prefix="/ti", tags=["threat-intel"])

class TIStatus(BaseModel):
    enabled: bool
    loaded_at: float
    counts: Dict[str, int]
    sources: Dict[str, str]
    score_bumps: Dict[str, int]

@router.get("/status", response_model=TIStatus)
def get_status(u: models.User = Depends(current_user)):
    return ti_status()

@router.post("/reload", response_model=TIStatus)
def post_reload(u: models.User = Depends(current_user)):
    return ti_reload()

@router.get("/lookup_ip", response_model=dict)
def ti_lookup_ip(ip: str = Query(..., description="IPv4/IPv6")):
    return lookup_ip(ip)

@router.get("/check_email_domain", response_model=dict)
def ti_check_email_domain(email: str):
    return check_email_domain(email)

# app/pydantic_compat.py
from typing import Any

def model_to_dict(model: Any, **kwargs) -> dict:
    """
    Converting a Pydantic model to a dict in a way that's compatible with
    both Pydantic v1 (.dict) and v2 (.model_dump).
    Any keyword args (e.g., exclude_unset=True) are forwarded.
    """
    if hasattr(model, "model_dump"):
        return model.model_dump(**kwargs)  # Pydantic v2
    return model.dict(**kwargs)           # Pydantic v1

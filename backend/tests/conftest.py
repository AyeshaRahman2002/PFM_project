# backend/tests/conftest.py
import os, sys
# add the backend folder (which contains the app/ package) to sys.path
ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

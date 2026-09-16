# config.py - Shared settings (port, host, keys)
# [IMPROVEMENT]: Moved hardcoded settings out of Python to a shared JSON file.
import json
import os
from shared.jsonkey import JsonKeys

_config_path = os.path.join(os.path.dirname(__file__), "config.json")
with open(_config_path, "r") as f:
    _cfg = json.load(f)

HOST = _cfg[JsonKeys.HOST]
PORT = _cfg[JsonKeys.PORT]
SENDER_ID = _cfg[JsonKeys.SENDER_ID]

# Encode keys to bytes as required by AES/HMAC algorithms
AES_KEY = _cfg[JsonKeys.AES_KEY].encode("utf-8")
HMAC_KEY = _cfg[JsonKeys.HMAC_KEY].encode("utf-8")

FRAME_COUNT = _cfg[JsonKeys.FRAME_COUNT]
FRAME_DELAY = _cfg[JsonKeys.FRAME_DELAY]
LOG_FILE = "logs/receiver.log"
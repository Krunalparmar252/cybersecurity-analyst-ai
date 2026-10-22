import os
from pathlib import Path


def _load_env_file():
    if "GROQ_API_KEY" not in os.environ:
        for path in [Path(".env"), Path(__file__).resolve().parent.parent / ".env"]:
            if path.is_file():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                key, val = line.split("=", 1)
                                key = key.strip()
                                val = val.strip().strip("'\"")
                                if key and key not in os.environ:
                                    os.environ[key] = val
                except Exception:
                    pass
                break


_load_env_file()

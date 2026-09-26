"""Root launcher: `python main.py` or `python -m src.main` both work."""
from src.main import main

if __name__ == "__main__":
    raise SystemExit(main())
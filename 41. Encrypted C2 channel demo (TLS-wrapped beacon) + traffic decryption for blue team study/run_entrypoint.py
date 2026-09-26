import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "app"))

from run import main

if __name__ == "__main__":
    main()
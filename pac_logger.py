"""
Utility module for setting up application logging.
"""

import logging
import sys
import config

# Set log format
log_formatter = logging.Formatter("%(asctime)s:%(name)s:%(levelname)s:%(message)s")

# Set console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)

# Set file handler
file_handler = logging.FileHandler(config.LOG_FILE)
file_handler.setFormatter(log_formatter)

logger = logging.getLogger("pacscan")
logger.setLevel(logging.DEBUG)
logger.addHandler(console_handler)
logger.addHandler(file_handler)


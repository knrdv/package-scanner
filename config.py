"""
This is a configuration file.
"""
from pathlib import Path

LOG_FILE = "pacscan.log"
LOG_FORMAT = "%(asctime)s:%(name)s:%(levelname)s:%(message)s"

SUPPORTED_PACKAGE_MGRS = ["apt"]

BASE_PATH = Path().absolute()
PKG_SCAN_DIR = BASE_PATH / "scan_results"
PKG_SCAN_FILE = "installed_packages.json"

PKG_ANALYSIS_DIR = BASE_PATH / "analysis_results"
PKG_ANALYSIS_FILE = "analysis_report.json"
PKG_ANALYSIS_MALFORMED = "analysis_malformed.json"

NVD_DB = PKG_SCAN_DIR /"cpe_db.xml"
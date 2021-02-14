"""
This is a configuration file.
"""
import os

LOG_FILE = "pacscan.log"

SUPPORTED_PACKAGE_MGRS = ["apt"]

BASE_PATH = os.path.dirname(os.path.realpath(__file__))
PKG_SCAN_DIR = os.path.join(BASE_PATH,"scan_results")
PKG_SCAN_FILE = "installed_packages.json"

PKG_ANALYSIS_DIR = os.path.join(BASE_PATH,"analysis_results")
PKG_ANALYSIS_FILE = "analysis_report.json"
PKG_ANALYSIS_MALFORMED = "analysis_malformed.json"

NVD_DB = os.path.join(PKG_SCAN_DIR, "cpe_db.xml")
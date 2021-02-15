#!/usr/bin/python3

from scanner import PackageScanner
from analyzer import Analyzer
import config
import logging

logging.basicConfig(level=logging.DEBUG, format=config.LOG_FORMAT, filename=config.LOG_FILE)
logger = logging.getLogger(__name__)

def main():
	"""
	Main function of packet scanner when running from cmdline.
	"""
	ps = PackageScanner()
	packages = ps.getInstalledPackages()
	#print(packages)
	ps.saveScanResults()

	an = Analyzer()
	an.loadFromFile(config.PKG_SCAN_DIR + "/" + config.PKG_SCAN_FILE)
	#an.loadFromPackageCont(packages)
	an.analyze()
	#an.saveAnalysisResults()

if __name__ == "__main__":
	main()
"""
This module is used for analyzing scanned packages.
"""
from scanner import PackageContainer
from scanner import Package
from pathlib import Path
import logging
import requests
import json
import config
import time

logging.basicConfig(level=logging.DEBUG, format=config.LOG_FORMAT, filename=config.LOG_FILE)
logger = logging.getLogger(__name__)

class Analyzer:

	def __init__(self):
		self.packages = PackageContainer()
		self.processed = PackageContainer()
		self.malformed = PackageContainer()
		self.malformed_ctr = 0
		self.processed_ctr = 0
		self.cve_cache = {}
		
	def loadFromFile(self, file):
		"""
		Load packages from JSON file.
		"""
		scan_results = Path(file)
		if not scan_results.is_file():
			logger.error(f"File {scan_results} does not exist")
			raise ValueError(f"File {scan_results} does not exist")
		with open(scan_results) as json_file:
			data = json.load(json_file)
			self.packages = PackageContainer(data)
		logger.info(f"Loaded packages from {scan_results}")

	def loadFromPackageCont(self, pkg_cont):
		"""
		Load from package container
		"""
		self.packages = pkg_cont
		logger.info("Loaded packages from package container.")

	def nvdGetCPE(self, pkg, fromdb=False) -> tuple:
		"""
		Get packages CVE info results from NVD API or downloaded database
		"""
		major_version = None
		minor_version = None
		if "+" in pkg.version:
			sres = pkg.version.split("+")
			major_version = sres[0]
			minor_version = sres[1]
		elif "~" in pkg.version:
			sres = pkg.version.split("~")
			major_version = sres[0]
			minor_version = sres[1]
		elif "-" in pkg.version:
			sres = pkg.version.split("-")
			major_version = sres[0]
			minor_version = sres[1]

		if not major_version: major_version = pkg.version

		# First try requesting bot major and minor versions
		cpematch = f"cpeMatchString=cpe:2.3:*:*:{pkg.name}:{major_version}:{minor_version}"
		r_str = f"https://services.nvd.nist.gov/rest/json/cpes/1.0?{cpematch}&addOns=cves"
		r = requests.get(r_str)
		json_response = json.loads(r.text)
		r.close()

		print(r_str)
		if json_response["totalResults"] == 0:
			old_response = json_response
			logger.info(f"No vulns found after major+minor check:{pkg.name} {pkg.version}")
			logger.info(f"Checking only with major version")
			cpematch = f"cpeMatchString=cpe:2.3:*:*:{pkg.name}:{major_version}"
			r_str = f"https://services.nvd.nist.gov/rest/json/cpes/1.0?{cpematch}&addOns=cves"
			r = requests.get(r_str)
			json_response = json.loads(r.text)
			r.close()

			# If new response has a minor version detected and old doesnt, keep the old result
			if json_response["totalResults"] > 0:
				if json_response["result"]["cpes"][0]["cpe23Uri"].split(":")[6] != "":
					json_response = old_response

		if not "result" in json_response:
			logger.warning(f"MALFORMED: No result field found for: {pkg.name}")
			self.malformed.add(pkg)
			return (None, None)

		if json_response["totalResults"] == 0:
			logger.info(f"No vulns found:{pkg.name} {pkg.version}")
			return (None, None)

		try:
			if json_response["result"]["cpeCount"] > 1:
				logger.warning(f"More than 1 cpe found for package:{pkg.name}, version:{pkg.version}")
		except KeyError as e:
			self.malformed.add(pkg)
			logger.warning(f"MALFORMED: Package version {pkg.version}")
			return (None, None)

		try:
			cpeid = json_response["result"]["cpes"][0]["cpe23Uri"]
			cves = json_response["result"]["cpes"][0]["vulnerabilities"]
		except IndexError as e:
			logger.info(f"No vulnerabilities found for: {pkg.name}")
			return (cpeid, None)

		return (cpeid, cves)

	def nvdGetCVE(self, cves : list) -> dict:
		"""
		Populate CVE severity info for every cve in package.
		"""
		base_request = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
		cve_dict = {}
		for cve in cves:
			if cve in self.cve_cache:
				cve_dict[cve] = self.cve_cache[cve]
				continue
			r = requests.get(base_request + cve)
			json_response = json.loads(r.text)
			r.close()
			severity = json_response["result"]["CVE_Items"][0]["impact"]["baseMetricV2"]["severity"]
			self.cve_cache[cve] = severity
			cve_dict[cve] = severity
		return cve_dict

	def printStatistics(self):
		"""
		Print statistics after finishing analysis.
		"""
		pass

	def saveAnalysisResults(self) -> None:
		"""
		Save results of last analysis run to a file.
		"""
		if not config.PKG_ANALYSIS_DIR.is_dir():
			config.PKG_ANALYSIS_DIR.mkdir()

		results_file_path = config.PKG_ANALYSIS_DIR / config.PKG_ANALYSIS_FILE
		self.processed.toFile(results_file_path)

		logger.info(f"Analysis results saved to:{results_file_path}")

	def saveAnalysisMalformed(self) -> None:
		"""
		Save malformed packages of last analysis run to a file.
		"""
		if not config.PKG_ANALYSIS_DIR.is_dir():
			config.PKG_ANALYSIS_DIR.mkdir()

		results_file_path = config.PKG_ANALYSIS_DIR / config.PKG_ANALYSIS_MALFORMED
		self.malformed.toFile(results_file_path)

		logger.info(f"Malformed results saved to: {results_file_path}")

	def analyze(self):
		"""
		Perform package analysis.
		"""
		if not self.packages:
			logger.error("Package Container empty, please scan for packages first")
			raise ValueError("Empty package container.")

		container_size = self.packages.size()
		ctr = 1
		logger.info(f"Analyzing {str(container_size)} packages")

		for pkg in self.packages:
			if ctr == 2:
				break
			cpeid, cves = self.nvdGetCPE(pkg)
			time.sleep(0.4)
			if cpeid:
				if cves:
					cve_dict = self.nvdGetCVE(cves)
					pkg.updatePackage(cpeid=cpeid, cves=cve_dict)
					self.processed.add(pkg)
				else:
					pkg.updatePackage(cpeid=cpeid)
					self.processed.add(pkg)
				logger.info(f"Updated package: {pkg.name}")
			ctr += 1

		self.saveAnalysisMalformed()
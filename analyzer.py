"""
This module is used for analyzing scanned packages.
"""
from scanner import PackageContainer
from scanner import Package
import logging
import sys
import requests
import json
import config
import os
import time

logger = logging.getLogger(__name__)

class Analyzer:

	def __init__(self):
		self.packages = PackageContainer()
		self.malformed = PackageContainer()
		self.malformed_ctr = 0
		self.processed_ctr = 0
		self.cve_cache = {}
		

	def loadFromFile(self, file):
		"""
		Load packages from JSON file.
		"""
		if not os.path.exists(file):
			logger.error("File " + file + " does not exist.")
			sys.exit()
		with open(file) as json_file:
			data = json.load(json_file)
			self.packages = PackageContainer(data)
		logger.info("Loaded packages from JSON file")

	def loadFromPackageCont(self, pkg_cont):
		"""
		Load from package container
		"""
		self.packages = pkg_cont
		logger.info("Loaded packages from package container.")

	def nvdGETCPE(self, pkg, fromdb=False) -> list:
		"""
		Get packages CVE info results from NVD API or downloaded database
		"""
		major_version = None
		print(pkg.version)
		if "+" in pkg.version:
			major_version = pkg.version.split("+")[0]
		elif "~" in pkg.version:
			major_version = pkg.version.split("~")[0]
		elif "-" in pkg.version:
			major_version = pkg.version.split("-")[0]

		if not major_version: major_version = pkg.version
		cpematch = "cpeMatchString=cpe:2.3:*:*" + ":" + pkg.name + ":" + major_version
		r_str = "https://services.nvd.nist.gov/rest/json/cpes/1.0?" + cpematch + "&addOns=cves"
		print("Request: " + r_str)
		r = requests.get(r_str)
		json_response = json.loads(r.text)
		r.close()

		if not "result" in json_response:
			logger.warning("MALFORMED: No result field found for: " + pkg.name)
			self.malformed.add(pkg)
			return [None, None]

		if json_response["totalResults"] == 0:
			logger.info("No vulns found:" + pkg.name + " " + pkg.version)
			return [None, None]

		try:
			if json_response["result"]["cpeCount"] > 1:
				logger.warning("More than 1 cpe found for package:" + pkg.name + ", version:" + pkg.version)
		except KeyError as e:
			self.malformed.add(pkg)
			logger.warning("MALFORMED: Package version " + pkg.version)
			return [None, None]

		try:
			cpeid = json_response["result"]["cpes"][0]["cpe23Uri"]
			cves = json_response["result"]["cpes"][0]["vulnerabilities"]
		except IndexError as e:
			logger.info("No vulnerabilities found for: " + pkg.name)
			#print(json.dumps(json_response, indent=4, sort_keys=True))
			return [cpeid, None]

		return [cpeid, cves]

	def nvdGETCVE(self, cves : list) -> None:
		"""
		Populate CVE severity info for every cve in package.
		"""
		print("IN GETCVE")
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
		if not os.path.isdir(config.PKG_ANALYSIS_DIR):
			os.mkdir(config.PKG_ANALYSIS_DIR)

		results_file_path = os.path.join(config.PKG_ANALYSIS_DIR, config.PKG_ANALYSIS_FILE)
		self.packages.toFile(results_file_path)

		logger.info("Analysis results saved to:" + results_file_path)

	def saveAnalysisMalformed(self) -> None:
		"""
		Save malformed packages of last analysis run to a file.
		"""
		if not os.path.isdir(config.PKG_ANALYSIS_DIR):
			os.mkdir(config.PKG_ANALYSIS_DIR)

		results_file_path = os.path.join(config.PKG_ANALYSIS_DIR, config.PKG_ANALYSIS_MALFORMED)
		self.malformed.toFile(results_file_path)

		logger.info("Malformed results saved to:" + results_file_path)

	def analyze(self):
		"""
		Perform package analysis.
		"""
		if not self.packages:
			logger.error("Package Container empty, please scan for packages first")
			sys.exit()

		container_size = self.packages.size()
		ctr = 1
		logger.info("Analyzing " + str(container_size) + " packages")

		for pkg in self.packages:
			if ctr == 3:
				break
			print("Checking package " + str(ctr) + "/" + str(container_size))
			cpeid, cves = self.nvdGETCPE(pkg)
			time.sleep(0.4)
			if cpeid:
				if cves:
					cve_dict = self.nvdGETCVE(cves)
					pkg.updatePackage(cpeid=cpeid, cves=cve_dict)
				else:
					pkg.updatePackage(cpeid=cpeid)
				logger.info("Updated package: " + pkg.name)
			ctr += 1

		self.saveAnalysisMalformed()
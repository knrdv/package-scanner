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

logger = logging.getLogger("pacscan")

class Analyzer:

	def __init__(self):
		self.packages = PackageContainer()
		self.malformed = PackageContainer()
		

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

	def nvdGET(self, pkg, fromdb=False) -> list:
		"""
		Get packages CVE info results from NVD API or downloaded database
		"""
		cpematch = "cpeMatchString=cpe:2.3:*:*" + ":" + pkg.name + ":" + pkg.version.split("-")[0]
		r_str = "https://services.nvd.nist.gov/rest/json/cpes/1.0?" + cpematch + "&addOns=cves"
		print("Request: " + r_str)
		r = requests.get(r_str)
		json_response = json.loads(r.text)
		r.close()
		#print(json.dumps(json_response, indent=4, sort_keys=True))

		try:
			if json_response["result"]["cpeCount"] > 1:
				logger.warning("More than 1 cpe found for package:" + pkg.name)
		except KeyError as e:
			self.malformed.add(pkg)
			logger.warning("Found malformed package version: " + pkg.version)
			return [None, None]

		try:
			cpeid = json_response["result"]["cpes"][0]["cpe23Uri"]
			cves = json_response["result"]["cpes"][0]["vulnerabilities"]
		except IndexError as e:
			print(e)
			#print(json.dumps(json_response, indent=4, sort_keys=True))
			return [None, None]

		return [cpeid, cves]

	def findVersion(self, nvdAll):
		"""
		From all NVD results, determine best suiting version of package.
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
			if ctr == 10:
				break
			print("Checking package " + str(ctr) + "/" + str(container_size))
			cpeid, cves = self.nvdGET(pkg)
			time.sleep(0.8)
			if cpeid:
				pkg.updatePackage(cpeid=cpeid, cves=cves)
				logger.info("Updated package: " + pkg.name)
			ctr += 1

		self.saveAnalysisMalformed()
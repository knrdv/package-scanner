"""
Scanner module

This module implements local package scanner.
"""
import subprocess
import logging
import config
from pathlib import Path
import json

logging.basicConfig(level=logging.DEBUG, format=config.LOG_FORMAT, filename=config.LOG_FILE)
logger = logging.getLogger(__name__)

class Package:
	"""
	Represents a package.
	"""
	def __init__(self, name="", version="", architecture="", vendor="", description="", cves:dict=None, cpeid="", pdict:dict=None):
		self.name = name
		self.version = version
		self.architecture = architecture
		self.vendor = vendor
		self.description = description
		self.cves = cves
		self.cpeid = cpeid

		if pdict:
			if "name" in pdict: self.name = pdict["name"]
			if "version" in pdict: self.version = pdict["version"]
			if "architecture" in pdict: self.architecture = pdict["architecture"]
			if "vendor" in pdict: self.vendor = pdict["vendor"]
			if "description" in pdict: self.description = pdict["description"]
			if "cves" in pdict: self.cves = pdict["cves"]
			if "cpeid" in pdict: self.cpeid = pdict["cpeid"]

	def __str__(self):
		return f"\nName:{self.name}\n" \
				f"Version:{self.version}\n" \
				f"Arch:{self.architecture}\n" \
				f"Vendor:{self.vendor}\n" \
				f"Description:{self.description}\n" \
				f"CVEs:{str(self.cves)}\n" \
				f"cpeid:{self.cpeid}"

	def updatePackage(self, name=None, version=None, architecture=None, vendor=None, description=None, cves:dict=None, cpeid:dict=None):
		if name: self.name = name
		if version: self.version = version
		if architecture: self.architecture = architecture
		if vendor: self.vendor = vendor
		if description: self.description = description
		if cves: self.cves = cves
		if cpeid: self.cpeid = cpeid


class PackageContainer:
	"""
	Represents a package container
	"""
	def __init__(self, json_list=[]):
		self.packages = []

		if json_list:
			for entry in json_list:
				self.packages.append(Package(pdict=entry))
			logger.info("Loaded PackageContainer from JSON dict entries")

	def __str__(self):
		retstr = ""
		for p in self.packages:
			retstr += str(p) + "\n"
		return retstr

	def __iter__(self):
		return self.packages.__iter__()

	def __next__(self):
		return self.packages.__next__()

	def __getitem__(self, key):
		return self.packages.__getitem__(key)

	def size(self) -> int:
		"""
		Return container size.
		"""
		return len(self.packages)

	def add(self, package : Package) -> None:
		"""
		Add new package.
		"""
		self.packages.append(package)

	def toJSON(self) -> str:
		"""
		Format to JSON.
		"""
		new_packages = []
		for p in self.packages:
			new_packages.append(p.__dict__)
		json_out = json.dumps(new_packages, indent=4)
		return json_out

	def toFile(self, file_path) -> None:
		"""
		Save JSON representation of package container to file file_path.
		"""
		json_repr = self.toJSON()
		
		with open(file_path, "w") as f:
			f.write(json_repr)			

class PackageScanner:
	"""
	Used for scanning local system for installed packages.
	"""
	def __init__(self):
		self.installed_packages = PackageContainer()
		self.package_manager = None

	def getInstalledPackages(self) -> PackageContainer:
		"""
		Get all installed packages on this machine.
		"""
		self.getPackageManager()
		if self.package_manager == "apt":
			packages = subprocess.check_output(["apt", "list", "--installed"], encoding='UTF-8', universal_newlines=True)
			packages = packages.split("\n")[1:-1]
		else:
			logger.error("Package manager not supported for extracting packages.")
			raise ValueError("Package manager unsupported")

		# Parse packages to self.installed_packages
		self.parsePackages(packages)

		logger.info("Installed packages collected")
		return self.installed_packages

	def getPackageManager(self) -> None:
		"""
		Get installed package manager and check for support.
		"""
		for pkgmgr in config.SUPPORTED_PACKAGE_MGRS:
			if subprocess.run(["which", pkgmgr]).returncode == 0:
				self.package_manager = pkgmgr
				return
		logger.error("Supported package manager not found, aborting.")
		raise ValueError("Package manager unsupported")

	def saveScanResults(self, out_path=None) -> None:
		"""
		Save results of last run to a file.
		"""
		scan_dir = Path(config.PKG_SCAN_DIR)
		if not scan_dir.is_dir():
			scan_dir.mkdir()
			logger.info(f"Created scan results directory at {config.PKG_SCAN_DIR}")

		json_results = self.installed_packages.toJSON()

		scan_file = Path(config.PKG_SCAN_FILE)
		results_path = scan_dir / scan_file
		with open(results_path, "w+") as f:
			f.write(json_results)

		logger.info(f"Scan results saved to:{results_path}")

	def parsePackages(self, packages_list) -> None:
		"""
		Parse package to extract relevant inormation.
		"""
		if self.package_manager == "apt":
			for package in packages_list:
				package = package.strip().split(" ")
				name = package[0].split("/")[0]
				version = package[1]
				architecture = package[2]
				self.installed_packages.add(Package(name=name, version=version, architecture=architecture))
		else:
			logger.error("Package manager parser not supported.")
			raise ValueError("Package manager unsupported")
		logger.info("Packages parsed successfully")
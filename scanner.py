"""
Scanner module

This module implements local package scanner.
"""
import subprocess
import logging
import config
import sys

logger = logging.getLogger("pacscan")

class PackageScanner:
	"""
	Used for scanning local system for installed packages.
	"""

	def __init__(self):
		self.installed_packages = PackageContainer()
		self.package_manager = None

	def getInstalledPackages(self) -> None:
		"""
		Get all installed packages on this machine.
		"""
		self.getPackageManager()
		if self.package_manager == "apt":
			packages = subprocess.check_output(["apt", "list", "--installed"], encoding='UTF-8', universal_newlines=True)
			packages = packages.split("\n")[1:-1]
		else:
			logger.error("Package manager not supported for extracting packages.")
			sys.exit()

		# Parse packages to self.installed_packages
		self.parsePackages(packages)

		self.installed_packages.print()

	def getPackageManager(self) -> None:
		"""
		Get installed package manager and check for support.
		"""
		for pkgmgr in config.SUPPORTED_PACKAGE_MGRS:
			if subprocess.run(["which", pkgmgr]).returncode == 0:
				self.package_manager = pkgmgr
				return
		logger.error("Supported package manager not found, aborting.")
		sys.exit()

	def saveScanResults(self) -> None:
		"""
		Save results of last run to a file.
		"""
		pass

	def parsePackages(self, packages_list) -> None:
		if self.package_manager == "apt":
			for package in packages_list:
				package = package.strip().split(" ")
				name = package[0].split("/")[0]
				version = package[1]
				architecture = package[2]
				self.installed_packages.add(Package(name, version, architecture))
		else:
			logger.error("Package manager parser not supported.")
			sys.exit()

class Package:
	"""
	Used to represent a package.
	"""
	def __init__(self, name=None, version=None, architecture=None):
		self.name = name
		self.version = version
		self.architecture = architecture

class PackageContainer:
	"""
	Represents a package container
	"""
	def __init__(self):
		self.packages = []

	def add(self, package : Package):
		self.packages.append(package)

	def print(self):
		for p in self.packages:
			print(p.name + " " + p.version + " " + p.architecture)

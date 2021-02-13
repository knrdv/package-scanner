"""
Scanner module

This module implements local package scanner.
"""

logger = logging.getLogger("pacscan")

class PackageScanner:
	"""
	Used for scanning local system for installed packages.
	"""

	def __init__(self):
		pass

	def getInstalledPackages(self) -> list:
		"""
		Get all installed packages on this machine.
		"""
		pass

	def saveScanResults(self) -> None:
		"""
		Save results of last run.
		"""
		pass
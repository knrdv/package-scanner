#!/usr/bin/python3

from pac_logger import logger
from scanner import PackageScanner

def main():
	"""
	Main function of packet scanner when running from cmdline.
	"""
	ps = PackageScanner()
	packages = ps.getInstalledPackages()


if __name__ == "__main__":
	main()
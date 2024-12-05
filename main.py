#!/usr/bin/python3
from patch_manager import PatchManager
from package_manager import PackageManager
from context import ContextManager

def main():
  ctx = ContextManager()
  # Will create values for package_homes, vulnerabilities
  pkg_mgr = PackageManager(ctx)
  pch_mgr = PatchManager(ctx)

    
if __name__=='__main__':
  main()

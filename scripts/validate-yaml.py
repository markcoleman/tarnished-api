#!/usr/bin/env python3
"""
Simple YAML validation script for Kubernetes manifests.
Validates all YAML files in the k8s/ directory.
"""

import sys
import os
import glob
import yaml

def validate_yaml_file(filepath):
    """Validate a single YAML file."""
    try:
        with open(filepath, 'r') as f:
            yaml.safe_load(f)
        print(f"✓ {filepath} is valid YAML")
        return True
    except yaml.YAMLError as e:
        print(f"✗ {filepath} has YAML syntax errors: {e}")
        return False
    except Exception as e:
        print(f"✗ Error reading {filepath}: {e}")
        return False

def main():
    """Main validation function."""
    # Find all YAML files in k8s directory
    yaml_files = glob.glob("k8s/*.yaml") + glob.glob("k8s/*.yml")
    
    if not yaml_files:
        print("No YAML files found in k8s/ directory")
        return 1
    
    print(f"Validating {len(yaml_files)} YAML files...")
    
    all_valid = True
    for yaml_file in sorted(yaml_files):
        if not validate_yaml_file(yaml_file):
            all_valid = False
    
    if all_valid:
        print("\nAll YAML files are syntactically valid!")
        return 0
    else:
        print("\nSome YAML files have syntax errors!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
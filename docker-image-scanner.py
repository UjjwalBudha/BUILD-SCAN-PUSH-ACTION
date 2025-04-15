import argparse
import json
import os
import sys
import subprocess
from typing import List, Dict

def scan_docker_image_with_trivy(image_id: str, severity: str = "HIGH,CRITICAL", exit_code: int = 1) -> int:
    """
    Scan Docker image using Trivy and return exit code.
    
    Args:
        image_id: Docker image ID or name to scan
        severity: Comma-separated list of severities to scan for
        exit_code: Exit code to return when vulnerabilities are found
        
    Returns:
        Exit code indicating success (0) or vulnerabilities found (exit_code)
    """
    try:
        cmd = [
            "trivy", 
            "image",
            "--exit-code", 
            str(exit_code),
            "--severity", 
            severity,
            image_id
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Print Trivy output
        if result.stdout:
            print(result.stdout)
        
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Error executing Trivy: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1

def main():
    parser = argparse.ArgumentParser(description="Scan Docker images using Trivy")
    parser.add_argument(
        "--image",
        required=True,
        help="Docker image ID or path to scan"
    )
    parser.add_argument(
        "--severity",
        default="HIGH,CRITICAL",
        help="Comma-separated list of vulnerability severities to scan for"
    )
    parser.add_argument(
        "--exit-code",
        type=int,
        default=1,
        help="Exit code when vulnerabilities are found"
    )
    
    args = parser.parse_args()
    
    # For image path, load it and get the image ID
    if args.image.startswith("/") or args.image.startswith("./"):
        # Looks like a file path
        try:
            result = subprocess.run(
                ["docker", "load", "--input", args.image],
                capture_output=True, 
                text=True, 
                check=True
            )
            # Extract image ID
            for line in result.stdout.splitlines():
                if "Loaded image ID: " in line:
                    image_id = line.replace("Loaded image ID: ", "").strip()
                    break
                elif "Loaded image: " in line:
                    image_id = line.replace("Loaded image: ", "").strip()
                    break
            else:
                print(f"Failed to extract image ID from docker load output", file=sys.stderr)
                sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"Error loading Docker image: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Use the image ID/name directly
        image_id = args.image

    exit_code = scan_docker_image_with_trivy(
        image_id=image_id,
        severity=args.severity,
        exit_code=args.exit_code
    )
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

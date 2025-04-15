import argparse
import json
import os
import sys
import subprocess
from typing import List, Dict, Any, Tuple

def scan_docker_image_with_trivy(image_id: str, severity: str = "HIGH,CRITICAL", exit_code: int = 1, format_output: str = "table") -> Tuple[int, Dict[str, Any]]:
    """
    Scan Docker image using Trivy and return exit code and scan results.
    
    Args:
        image_id: Docker image ID or name to scan
        severity: Comma-separated list of severities to scan for
        exit_code: Exit code to return when vulnerabilities are found
        format_output: Output format (table, json)
        
    Returns:
        Tuple containing exit code and scan results (if json format was used)
    """
    try:
        # First run a JSON scan to get structured data for reporting
        json_cmd = [
            "trivy", 
            "image",
            "--exit-code", 
            str(exit_code),
            "--severity", 
            severity,
            "--format", 
            "json",
            image_id
        ]
        
        json_result = subprocess.run(json_cmd, capture_output=True, text=True)
        scan_data = {}
        
        if json_result.stdout:
            try:
                scan_data = json.loads(json_result.stdout)
            except json.JSONDecodeError:
                print("Failed to parse Trivy JSON output", file=sys.stderr)
        
        # If user requested table format, run again to get human-readable output
        if format_output == "table":
            table_cmd = [
                "trivy", 
                "image",
                "--exit-code", 
                str(exit_code),
                "--severity", 
                severity,
                image_id
            ]
            
            table_result = subprocess.run(table_cmd, capture_output=True, text=True)
            
            # Print the human-readable output
            if table_result.stdout:
                print(table_result.stdout)
            
            if table_result.stderr:
                print(table_result.stderr, file=sys.stderr)
            
            return table_result.returncode, scan_data
        
        # If JSON output was requested, we already have the data
        if json_result.stderr:
            print(json_result.stderr, file=sys.stderr)
            
        return json_result.returncode, scan_data
    
    except subprocess.CalledProcessError as e:
        print(f"Error executing Trivy: {e}", file=sys.stderr)
        return 1, {}
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1, {}

def generate_security_report(scan_data: Dict[str, Any], image_name: str) -> str:
    """
    Generate a detailed security report from scan data
    
    Args:
        scan_data: The scan results from Trivy
        image_name: Name of the image that was scanned
    
    Returns:
        Formatted security report as a string
    """
    if not scan_data:
        return "No scan data available."
    
    report = []
    
    # Add header
    report.append("=" * 80)
    report.append(f"DETAILED SECURITY SCAN REPORT FOR: {image_name}")
    report.append("=" * 80)
    
    # Check if the scan data has results
    if "Results" not in scan_data:
        report.append("No vulnerability data found in scan results.")
        return "\n".join(report)
    
    # Process each result (typically OS packages and language-specific dependencies)
    total_vulnerabilities = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    
    for result in scan_data["Results"]:
        target = result.get("Target", "Unknown")
        vulnerabilities = result.get("Vulnerabilities", [])
        
        if not vulnerabilities:
            continue
            
        total_vulnerabilities += len(vulnerabilities)
        report.append(f"\n## Target: {target}")
        report.append(f"Found {len(vulnerabilities)} vulnerabilities\n")
        
        # Group vulnerabilities by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "UNKNOWN": []}
        
        for vuln in vulnerabilities:
            severity = vuln.get("Severity", "UNKNOWN")
            severity_counts[severity] += 1
            by_severity[severity].append(vuln)
        
        # Report on each severity level, starting with most critical
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            vulns = by_severity[severity]
            if not vulns:
                continue
                
            report.append(f"### {severity} Severity: {len(vulns)} found")
            
            # Print details for each vulnerability of this severity
            for i, vuln in enumerate(vulns, 1):
                vuln_id = vuln.get("VulnerabilityID", "Unknown")
                pkg_name = vuln.get("PkgName", "Unknown")
                installed = vuln.get("InstalledVersion", "Unknown")
                fixed = vuln.get("FixedVersion", "Not available")
                title = vuln.get("Title", "No description available")
                
                report.append(f"{i}. {vuln_id} in {pkg_name}")
                report.append(f"   Installed: {installed}, Fixed: {fixed}")
                report.append(f"   Description: {title}")
                
                # Add references if available
                if "References" in vuln and vuln["References"]:
                    report.append("   References:")
                    for ref in vuln["References"][:3]:  # Limit to 3 references
                        report.append(f"   - {ref}")
                report.append("")
    
    # Add summary
    report.append("\n" + "=" * 80)
    report.append("SUMMARY")
    report.append("=" * 80)
    report.append(f"Total vulnerabilities found: {total_vulnerabilities}")
    for severity, count in severity_counts.items():
        if count > 0:
            report.append(f"- {severity}: {count}")
    
    return "\n".join(report)

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
    parser.add_argument(
        "--format",
        default="table",
        choices=["table", "json", "detailed"],
        help="Output format for scan results"
    )
    parser.add_argument(
        "--report-file",
        help="File path to write detailed report to"
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

    # Get format to use for output - if detailed, we'll use json under the hood
    format_output = "json" if args.format == "detailed" else args.format
    
    exit_code, scan_data = scan_docker_image_with_trivy(
        image_id=image_id,
        severity=args.severity,
        exit_code=args.exit_code,
        format_output=format_output
    )
    
    # Generate detailed report if requested
    if args.format == "detailed":
        report = generate_security_report(scan_data, image_id)
        
        if args.report_file:
            try:
                with open(args.report_file, 'w') as f:
                    f.write(report)
                print(f"Detailed report written to {args.report_file}")
            except Exception as e:
                print(f"Error writing report to file: {e}", file=sys.stderr)
        
        # Print the report to stdout
        print(report)
    elif args.format == "json" and scan_data:
        print(json.dumps(scan_data, indent=2))
    
    # Print summary for GitHub Actions
    print("\n## Docker Image Security Scan Summary")
    print("| Scanner | Status |")
    print("|---------|--------|")
    status = "✅ Completed" if exit_code == 0 else f"⚠️ Found vulnerabilities (Exit: {exit_code})"
    print(f"| Trivy   | {status} |")
    
    if scan_data and "Results" in scan_data:
        vuln_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for result in scan_data["Results"]:
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN")
                vuln_counts[severity] += 1
        
        print("\n### Vulnerability Count")
        print("| Severity | Count |")
        print("|----------|-------|")
        for severity, count in vuln_counts.items():
            if count > 0:
                print(f"| {severity} | {count} |")
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

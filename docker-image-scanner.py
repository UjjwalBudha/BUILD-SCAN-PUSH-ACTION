import argparse
import json
import os
import sys
import subprocess
import pathspec

from typing import List, Dict


def format_image_path(image_path: str) -> str:
    """Format the image path to use file:/// prefix with absolute path."""
    abs_path = os.path.abspath(image_path)
    return f"file://{abs_path}"


def scan_docker_image(image_path: str) -> List[Dict]:
    """Scan Docker image using trufflehog and return JSON results."""
    try:
        formatted_path = format_image_path(image_path)
        cmd = [
            "trufflehog",
            "docker",
            "--image",
            formatted_path,
            "--json",
            "--no-update",
            "--no-verification",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Error running trufflehog: {result.stderr}", file=sys.stderr)
            sys.exit(1)

        # Process output line by line as each line is a JSON object
        findings = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return findings
    except subprocess.CalledProcessError as e:
        print(f"Error executing trufflehog: {e}", file=sys.stderr)
        sys.exit(1)


def filter_results(findings: List[Dict], ignorepaths: str) -> List[Dict]:
    """Filter findings based on gitignore patterns."""
    try:
        with open(ignorepaths, "r") as fh:
            spec = pathspec.PathSpec.from_lines("gitwildmatch", fh)
    except FileNotFoundError:
        print(
            f"file {ignorepaths} not found in repository. Not filtering any findings."
        )
        return findings

    filtered_findings = []

    for finding in findings:
        file_path = str(finding["SourceMetadata"]["Data"]["Docker"]["file"])
        if spec.match_file(file_path):
            continue

        filtered_findings.append(finding)

    return filtered_findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--image",
        required=True,
        help="local tarball of your docker image",
    )
    parser.add_argument(
        "--ignorepaths",
        required=False,
        help="file with paths to ignore (in gitignore pattern format)",
        default=".truffleignore",
    )
    args = parser.parse_args()

    findings = scan_docker_image(args.image)

    # Filter results if patterns provided
    if args.ignorepaths:
        findings = filter_results(findings, args.ignorepaths)

    # Output results
    if findings:
        for finding in findings:
            file = (
                finding.get("SourceMetadata", {})
                .get("Data", {})
                .get("Docker", {})
                .get("file", "")
            )
            layer = (
                finding.get("SourceMetadata", {})
                .get("Data", {})
                .get("Docker", {})
                .get("layer", "")
            )
            redacted_secret = finding["Redacted"]
            print(
                f"Found unverified secret {redacted_secret} in file={file} layer={layer}"
            )
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

import subprocess
import sys
from typing import Optional, Tuple


def generate_attestation_report(report_data_hex: str) -> str:
    """
    Execute the Rust binary to generate a TDX attestation report.

    Args:
        report_data_hex (str): 64-byte report data as a hex string (128 hex characters)

    Returns:
        str: The serialized attestation report as a hex string

    Raises:
        ValueError: If report_data_hex is not exactly 128 hex characters
        subprocess.CalledProcessError: If the Rust binary execution fails
        RuntimeError: If the binary output cannot be parsed
    """
    # Validate input
    if len(report_data_hex) != 128:
        raise ValueError("report_data_hex must be exactly 128 hexadecimal characters (64 bytes)")

    # Verify hex string is valid
    try:
        int(report_data_hex, 16)
    except ValueError:
        raise ValueError("report_data_hex contains invalid hexadecimal characters")

    try:
        # Execute the Rust binary
        result = subprocess.run(
            ["./generate_attestation", report_data_hex],
            capture_output=True,
            text=True,
            check=True,
            timeout=30  # 30 second timeout
        )

        # Get the output and strip whitespace
        output = result.stdout.strip()

        if not output:
            raise RuntimeError("No output received from attestation generation binary")

        # Validate that output is hex
        try:
            int(output, 16)
        except ValueError:
            raise RuntimeError(f"Invalid hex output from binary: {output}")

        return output

    except subprocess.TimeoutExpired:
        raise RuntimeError("Attestation generation timed out after 30 seconds")
    except subprocess.CalledProcessError as e:
        error_msg = f"Attestation generation failed with exit code {e.returncode}"
        if e.stderr:
            error_msg += f": {e.stderr.strip()}"
        raise subprocess.CalledProcessError(e.returncode, e.cmd, e.output, e.stderr) from e


def verify_attestation_report(attestation_report_hex: str) -> Tuple[bool, str]:
    """
    Execute the Rust binary to verify a TDX attestation report and extract report_data.

    Args:
        attestation_report_hex (str): The serialized attestation report as a hex string

    Returns:
        Tuple[bool, str]: A tuple containing:
            - bool: True if verification succeeded, False otherwise
            - str: If successful, the extracted report_data as hex string; otherwise error message

    Raises:
        ValueError: If attestation_report_hex is not valid hex
        RuntimeError: If the binary execution fails unexpectedly
    """
    # Validate input is hex
    if not attestation_report_hex:
        raise ValueError("attestation_report_hex cannot be empty")

    try:
        int(attestation_report_hex, 16)
    except ValueError:
        raise ValueError("attestation_report_hex contains invalid hexadecimal characters")

    try:
        # Execute the Rust verification binary
        result = subprocess.run(
            ["./verify_attestation", attestation_report_hex],
            capture_output=True,
            text=True,
            timeout=30  # 30 second timeout
        )

        # Handle output based on success/failure
        verification_success = result.returncode == 0

        if verification_success:
            # On success, stdout contains the extracted report_data as hex
            report_data_hex = result.stdout.strip()
            if not report_data_hex:
                raise RuntimeError("Verification succeeded but no report_data was extracted")
            return True, report_data_hex
        else:
            # On failure, stderr contains the error message
            error_output = result.stderr.strip()
            return False, error_output if error_output else "Verification failed with no error message"

    except subprocess.TimeoutExpired:
        raise RuntimeError("Attestation verification timed out after 30 seconds")
    except Exception as e:
        raise RuntimeError(f"Unexpected error during verification: {str(e)}") from e


def main():
    """
    Example usage of the attestation functions.
    """
    # Example report data (64 bytes as hex - all zeros for demonstration)
    example_report_data = "7" * 128

    try:
        print("Generating attestation report...")
        attestation_report = generate_attestation_report(example_report_data)
        print(f"Generated attestation report: {attestation_report[:100]}...")  # Show first 100 chars

        print("\nVerifying attestation report...")
        is_valid, result_data = verify_attestation_report(attestation_report)

        print(f"Verification result: {'SUCCESS' if is_valid else 'FAILED'}")
        if is_valid:
            print(f"Extracted report_data: {result_data}")
            print(f"Original report_data: {example_report_data}")
            print(f"Report data match: {result_data.upper() == example_report_data.upper()}")
        else:
            print(f"Error message: {result_data}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    exit(main())

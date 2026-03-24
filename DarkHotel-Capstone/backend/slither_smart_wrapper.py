"""
SMART SLITHER WRAPPER v3.2 - Cross-Process Safe + Windows Compatible

Features:
1. UUID-based temp files (fix race condition for concurrent users)
2. Cross-process file-based lock for solc-select (safe for multi-worker deployments)
3. Smart version check before install (avoid slow downloads)
4. Graceful fallback with clear warnings for AI
5. Windows-compatible path handling

v3.2 Updates:
- Replaced threading.Lock with FileLock (cross-process safe via OS-level exclusive file creation)
- Supports multi-worker deployments (gunicorn -w N) without solc-select race conditions
- Stale lock auto-cleanup (timeout-based)

Strategy:
1. Try to detect Solidity version from pragma
2. Check if version installed, install only if needed
3. File-lock solc-select to prevent concurrent version switching (cross-process)
4. If fail → Return WARNING message for AI (not silent fail!)
"""
import subprocess
import json
import os
import re
import uuid
import threading
import platform
import tempfile
import time
from typing import Dict, List

# --- Cross-process file-based lock for solc-select ---
# threading.Lock only works within a single process.
# This file-based lock works across multiple workers (gunicorn -w N).

class FileLock:
    """
    Simple cross-process file lock using OS-level exclusive file creation.
    Works on both Windows and Linux. Safe for multi-worker deployments.
    """
    def __init__(self, lock_path: str, timeout: float = 120, poll_interval: float = 0.5):
        self.lock_path = lock_path
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._thread_lock = threading.Lock()  # Also prevent in-process races

    def acquire(self):
        self._thread_lock.acquire()
        start = time.monotonic()
        while True:
            try:
                # O_CREAT | O_EXCL: atomic create-or-fail (cross-process safe)
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                # Write PID for debugging
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return
            except FileExistsError:
                # Check if lock is stale (older than timeout)
                try:
                    lock_age = time.monotonic() - os.path.getmtime(self.lock_path)
                    if lock_age > self.timeout:
                        # Stale lock, remove and retry
                        try:
                            os.unlink(self.lock_path)
                        except OSError:
                            pass
                        continue
                except OSError:
                    pass

                if time.monotonic() - start > self.timeout:
                    self._thread_lock.release()
                    raise TimeoutError(f"Could not acquire solc lock after {self.timeout}s")
                time.sleep(self.poll_interval)

    def release(self):
        try:
            os.unlink(self.lock_path)
        except OSError:
            pass
        self._thread_lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        self.release()

# Cross-process lock file in temp directory
SOLC_LOCK = FileLock(os.path.join(tempfile.gettempdir(), "darkhotel_solc.lock"))

# Detect if running on Windows
IS_WINDOWS = platform.system() == "Windows"

class SmartSlitherWrapper:
    """
    Intelligent Slither wrapper that:
    - Auto-detects Solidity version
    - Tries to run Slither
    - On failure: Returns CLEAR WARNING (not "No vulnerabilities")
    - Never lies to AI about code safety!
    """

    def __init__(self):
        self.slither_path = "slither"
        self.has_solc_select = self._check_solc_select()

    def _check_solc_select(self) -> bool:
        """Check if solc-select is installed and working"""
        try:
            # On Windows, we need shell=True for some commands
            if IS_WINDOWS:
                result = subprocess.run(
                    'solc-select versions',
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=10
                )
            else:
                result = subprocess.run(
                    ['solc-select', 'versions'],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=10
                )
            return result.returncode == 0
        except Exception as e:
            print(f"[SlitherWrapper] solc-select check failed: {e}")
            return False

    def _get_installed_versions(self) -> set:
        """Get list of installed solc versions"""
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    'solc-select versions',
                    shell=True,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=10
                )
            else:
                result = subprocess.run(
                    ['solc-select', 'versions'],
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=10
                )
            if result.returncode == 0:
                # Parse output: "0.4.24 (current)\n0.8.0\n..."
                versions = set()
                for line in result.stdout.strip().split('\n'):
                    version = line.split()[0] if line.strip() else None
                    if version and version[0].isdigit():
                        versions.add(version)
                return versions
        except Exception as e:
            print(f"[SlitherWrapper] Failed to get installed versions: {e}")
        return set()

    def _ensure_solc_version(self, version: str) -> bool:
        """
        Ensure solc version is installed. Install only if needed.
        Returns True if version is ready to use.
        """
        installed = self._get_installed_versions()
        if version in installed:
            return True  # Already installed, no download needed

        # Version not installed, try to install
        try:
            result = subprocess.run(
                f"solc-select install {version}",
                shell=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120  # Installation can take time
            )
            return result.returncode == 0
        except:
            return False

    def _extract_solidity_version(self, code: str) -> str:
        """
        Extract Solidity version from pragma.
        Uses exact version from pragma if 3-part (e.g. 0.8.20).
        Falls back to known latest patch for 2-part (e.g. 0.8).
        Auto-installs via _ensure_solc_version if not available.
        """
        pragma_match = re.search(r'pragma\s+solidity\s+[\^~>=]*([\d.]+)', code)
        if pragma_match:
            version = pragma_match.group(1)
            parts = version.split('.')

            # If full 3-part version (0.8.20), use it directly
            if len(parts) == 3:
                return version

            # If 2-part (0.8), map to a known stable version
            if len(parts) == 2:
                major_minor = f"{parts[0]}.{parts[1]}"
                fallback_map = {
                    "0.4": "0.4.26",
                    "0.5": "0.5.17",
                    "0.6": "0.6.12",
                    "0.7": "0.7.6",
                    "0.8": "0.8.34"
                }
                return fallback_map.get(major_minor, "0.8.34")

        return None

    def _has_external_imports(self, code: str) -> bool:
        """Check if code has external imports that would cause compilation failure"""
        # Match imports like @openzeppelin, hardhat, etc.
        external_import = re.search(r'import\s+["\']@\w+', code)
        return external_import is not None

    def _strip_imports_and_inheritance(self, code: str) -> str:
        """
        Remove external imports and inheritance to allow basic Slither analysis.
        This is a fallback when full compilation fails.
        """
        # Remove import lines
        code = re.sub(r'import\s+["\'][^"\']+["\'];?\s*\n?', '', code)

        # Remove inheritance (is X, Y, Z) but keep contract name
        code = re.sub(r'(contract\s+\w+)\s+is\s+[^{]+', r'\1 ', code)

        # Remove modifier calls that reference removed contracts
        code = re.sub(r'\bnonReentrant\b', '', code)
        code = re.sub(r'\bonlyOwner\b', '', code)

        # Remove parent constructor calls like Ownable(msg.sender)
        code = re.sub(r'\bOwnable\s*\([^)]*\)', '', code)
        code = re.sub(r'\bReentrancyGuard\s*\([^)]*\)', '', code)
        code = re.sub(r'\bERC20\s*\([^)]*\)', '', code)
        code = re.sub(r'\bERC721\s*\([^)]*\)', '', code)

        # Clean up empty constructor if only had parent calls
        # constructor() Ownable(msg.sender) {} -> constructor() {}
        code = re.sub(r'constructor\s*\(\s*\)\s*\{\s*\}', 'constructor() {}', code)

        return code

    def analyze(self, contract_code: str, filename: str = "Contract.sol") -> Dict:
        """
        Smart analysis with graceful fallback (Thread-safe v3)

        Returns:
            {
                'success': True/False,
                'status': 'ok' | 'warning' | 'error',
                'message': 'Human readable status',
                'warnings': [...] or ['SLITHER_UNAVAILABLE: ...']
            }
        """
        # [v2] Generate unique filenames to prevent race conditions
        unique_id = str(uuid.uuid4())[:8]
        unique_filename = f"Contract_{unique_id}.sol"
        unique_json = f"output_{unique_id}.json"

        # Create temp file in system temp dir (avoid Unicode path issues with solc)
        temp_dir = os.path.join(tempfile.gettempdir(), 'darkhotel_slither')
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, unique_filename)
        json_output_path = os.path.join(temp_dir, unique_json)

        # Detect Solidity version BEFORE creating file
        detected_version = self._extract_solidity_version(contract_code)

        # [v3] Check for external imports - if present, try stripped version first
        has_imports = self._has_external_imports(contract_code)
        code_to_analyze = contract_code

        # [v3.1] Detect protections from ORIGINAL code BEFORE stripping
        # These modifiers get removed for compilation but LLM needs to know they exist
        stripped_protections = []
        if has_imports:
            if re.search(r'\bnonReentrant\b|ReentrancyGuard', contract_code):
                stripped_protections.append("ReentrancyGuard/nonReentrant")
            if re.search(r'\bonlyOwner\b|Ownable', contract_code):
                stripped_protections.append("onlyOwner/Ownable")
            code_to_analyze = self._strip_imports_and_inheritance(contract_code)

        try:
            # Write contract to temp file
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(code_to_analyze)

            # [v3] Use lock for solc-select to prevent concurrent version switching
            with SOLC_LOCK:
                slither_ran = False
                slither_error = None

                if detected_version and self.has_solc_select:
                    # Check/install version (fast if already installed)
                    if self._ensure_solc_version(detected_version):
                        # Build shell command that switches version then runs Slither
                        if IS_WINDOWS:
                            # Windows: use && for command chaining in cmd.exe
                            cmd = f'solc-select use {detected_version} && slither "{temp_path}" --json "{json_output_path}"'
                        else:
                            cmd = f'solc-select use {detected_version} && slither "{temp_path}" --json "{json_output_path}"'

                        try:
                            result = subprocess.run(
                                cmd,
                                shell=True,
                                capture_output=True,
                                text=True,
                                encoding='utf-8',
                                errors='replace',
                                timeout=90  # Increased timeout for Windows
                            )
                            slither_ran = True
                        except Exception as e:
                            slither_error = str(e)
                    else:
                        slither_error = f"Failed to install solc {detected_version}"

                # Fallback: Try running Slither without solc-select
                if not slither_ran:
                    cmd = f'slither "{temp_path}" --json "{json_output_path}"'
                    try:
                        result = subprocess.run(
                            cmd,
                            shell=True,
                            capture_output=True,
                            text=True,
                            encoding='utf-8',
                            errors='replace',
                            timeout=90
                        )
                        slither_ran = True
                    except subprocess.TimeoutExpired:
                        return self._create_warning_response(
                            detected_version,
                            reason="Slither timed out (>90s)"
                        )
                    except Exception as e:
                        return self._create_warning_response(
                            detected_version,
                            reason=f"Slither execution failed: {str(e)}"
                        )

            # [NEW] Check if JSON file was created (more reliable than stdout)
            if not os.path.exists(json_output_path):
                return self._create_warning_response(
                    detected_version,
                    reason="Slither produced no JSON output (likely compilation error)"
                )

            # [NEW] Try to parse JSON from FILE (not stdout)
            try:
                with open(json_output_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Check if we got valid results
                if 'results' not in data:
                    return self._create_warning_response(
                        detected_version,
                        reason="Slither output missing 'results' section"
                    )

                detectors = data.get('results', {}).get('detectors', [])

                # SUCCESS - Slither ran and returned results
                if len(detectors) == 0:
                    msg = 'Slither ran successfully, no vulnerabilities found'
                    if has_imports:
                        msg += ' (analyzed with imports stripped)'
                    return {
                        'success': True,
                        'status': 'ok',
                        'message': msg,
                        'warnings': ['No vulnerabilities detected by Slither']
                    }
                else:
                    # [IMPROVED] Parse vulnerabilities with more detail
                    warnings = []
                    for det in detectors:
                        vuln_type = det.get('check', 'Unknown')
                        impact = det.get('impact', 'Unknown')
                        desc = det.get('description', '')

                        # Extract file + line numbers
                        location = ""
                        if 'elements' in det and len(det['elements']) > 0:
                            elem = det['elements'][0]
                            source_mapping = elem.get('source_mapping', {})
                            lines = source_mapping.get('lines', [])
                            if lines:
                                location = f" (line {lines[0]})"

                        # Clean description (remove markdown formatting for AI)
                        clean_desc = desc.replace('`', '').replace('\t', ' ')[:150]
                        warnings.append(f"[{impact}] {vuln_type}{location}: {clean_desc}")

                    # [v3.1] Append stripped protections context for LLM
                    if stripped_protections:
                        protections_str = ', '.join(stripped_protections)
                        warnings.append(
                            f"⚠️ NOTE: Original code uses {protections_str} "
                            f"(removed for Slither compilation). "
                            f"Verify if above findings are still valid with these protections."
                        )

                    msg = f'Slither found {len(detectors)} issues'
                    if has_imports:
                        msg += ' (analyzed with imports stripped)'
                    return {
                        'success': True,
                        'status': 'ok',
                        'message': msg,
                        'warnings': warnings
                    }

            except json.JSONDecodeError:
                # Slither returned something but not valid JSON
                return self._create_warning_response(
                    detected_version,
                    reason="Slither output is not valid JSON (compilation likely failed)"
                )

        except subprocess.TimeoutExpired:
            return self._create_warning_response(
                detected_version,
                reason="Slither timed out (>60s)"
            )

        except FileNotFoundError:
            return self._create_warning_response(
                detected_version,
                reason="Slither not installed"
            )

        except Exception as e:
            return self._create_warning_response(
                detected_version,
                reason=f"Unexpected error: {str(e)}"
            )

        finally:
            # [v2] Clean up OUR unique temp files (not others')
            for filepath in [temp_path, json_output_path]:
                if os.path.exists(filepath):
                    try:
                        os.unlink(filepath)
                    except:
                        pass

    def _create_warning_response(self, detected_version: str, reason: str) -> Dict:
        """
        Create a WARNING response that tells AI clearly:
        "Slither failed, you need to analyze manually"

        This is BETTER than returning "No vulnerabilities" which is a LIE!
        """
        version_info = f" (Detected: Solidity {detected_version})" if detected_version else ""

        warning_message = f"⚠️ SLITHER UNAVAILABLE{version_info}: {reason}. " \
                         f"AI must perform MANUAL code review without static analysis assistance."

        return {
            'success': False,
            'status': 'warning',
            'message': reason,
            'warnings': [warning_message],
            'detected_version': detected_version
        }

    def get_warnings_for_ai(self, contract_code: str) -> List[str]:
        """
        Get warnings in format suitable for AI prompt

        Returns either:
        - ["No vulnerabilities detected by Slither"] (if Slither worked)
        - ["[High] Reentrancy at line 45"] (if Slither found issues)
        - ["⚠️ SLITHER UNAVAILABLE: ..."] (if Slither failed - CLEAR SIGNAL!)
        """
        result = self.analyze(contract_code)
        return result.get('warnings', [])


# Test
if __name__ == "__main__":
    wrapper = SmartSlitherWrapper()

    print("="*70)
    print("TESTING SMART SLITHER WRAPPER")
    print("="*70)

    # Test 1: Simple reentrancy
    test_code_1 = """
pragma solidity ^0.4.24;

contract VulnerableBank {
    mapping(address => uint) public balances;

    function withdraw() public {
        uint amount = balances[msg.sender];
        msg.sender.call.value(amount)("");  // REENTRANCY
        balances[msg.sender] = 0;
    }
}
"""

    print("\nTest 1: Reentrancy contract (Solidity 0.4.24)")
    print("-"*70)
    result1 = wrapper.analyze(test_code_1)
    print(f"Status: {result1['status']}")
    print(f"Message: {result1['message']}")
    print(f"Warnings: {result1['warnings']}")

    # Test 2: Real file
    print("\n\nTest 2: Real test file")
    print("-"*70)
    try:
        with open('../data/test-contracts-50/01_reentrancy_doc_7588.sol') as f:
            real_code = f.read()

        result2 = wrapper.analyze(real_code)
        print(f"Status: {result2['status']}")
        print(f"Message: {result2['message']}")
        print(f"Warnings:")
        for w in result2['warnings'][:3]:
            print(f"  - {w}")

        if len(result2['warnings']) > 3:
            print(f"  ... and {len(result2['warnings']) - 3} more")

    except FileNotFoundError:
        print("Test file not found")

    # Test 3: Check warning format for AI
    print("\n\nTest 3: AI-friendly format")
    print("-"*70)
    warnings_for_ai = wrapper.get_warnings_for_ai(test_code_1)
    print("AI will receive:")
    for w in warnings_for_ai:
        print(f"  {w}")

    print("\n" + "="*70)
    print("KEY FEATURE: If Slither fails, AI gets CLEAR WARNING")
    print("NOT a silent 'No vulnerabilities' lie!")
    print("="*70)

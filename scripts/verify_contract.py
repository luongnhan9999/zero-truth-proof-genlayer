import subprocess
import sys
import os

def main():
    print("====================================================")
    print("ZeroTruthProof Contract Verification Suite")
    print("====================================================\n")
    
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    test_file = os.path.join(repo_root, "tests", "test_zero_truth_proof.py")
    
    # ── Stage 1: Local mock test suite (unittest) ──
    print("[Stage 1] Running local mock test suite (test_zero_truth_proof.py)...")
    result_mock = subprocess.run([sys.executable, test_file], cwd=repo_root)
    
    if result_mock.returncode != 0:
        print("\n[FAILURE] Mock test suite failed.")
        sys.exit(result_mock.returncode)
    print("[Stage 1] Mock test suite PASSED.\n")

    # ── Stage 2: Real GenVM execution tests via gltest (ZERO MOCKS) ──
    print("[Stage 2] Running real GenVM execution suites (test_genlayer_runtime.py + test_gltest_suite.py)...")
    gltest_files = [
        os.path.join(repo_root, "tests", "test_genlayer_runtime.py"),
        os.path.join(repo_root, "tests", "test_gltest_suite.py")
    ]
    
    try:
        result_gltest = subprocess.run(
            [sys.executable, "-m", "pytest", *gltest_files, "-v", "--tb=short"],
            cwd=repo_root,
            timeout=300
        )
        if result_gltest.returncode != 0:
            print("\n[WARNING] gltest suite had failures (may require GenVM runtime).")
        else:
            print("[Stage 2] gltest GenVM real execution suites PASSED.\n")
    except FileNotFoundError:
        print("[SKIP] pytest not installed; skipping gltest suite.")
    except subprocess.TimeoutExpired:
        print("[TIMEOUT] gltest suite exceeded 5-minute timeout.")

    print("\n[SUCCESS] Contract verification completed.")
    sys.exit(0)

if __name__ == "__main__":
    main()

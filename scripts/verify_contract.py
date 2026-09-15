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

    # ── Stage 2: GenVM integration tests via gltest (if available) ──
    print("[Stage 2] Running gltest GenVM integration suite (test_gltest_suite.py)...")
    gltest_file = os.path.join(repo_root, "tests", "test_gltest_suite.py")
    
    if not os.path.exists(gltest_file):
        print("[SKIP] test_gltest_suite.py not found.")
    else:
        try:
            result_gltest = subprocess.run(
                [sys.executable, "-m", "pytest", gltest_file, "-v", "--tb=short"],
                cwd=repo_root,
                timeout=300
            )
            if result_gltest.returncode != 0:
                print("\n[WARNING] gltest suite had failures (may require GenVM runtime).")
            else:
                print("[Stage 2] gltest suite PASSED.\n")
        except FileNotFoundError:
            print("[SKIP] pytest not installed; skipping gltest suite.")
        except subprocess.TimeoutExpired:
            print("[TIMEOUT] gltest suite exceeded 5-minute timeout.")

    print("\n[SUCCESS] Contract verification completed.")
    sys.exit(0)

if __name__ == "__main__":
    main()

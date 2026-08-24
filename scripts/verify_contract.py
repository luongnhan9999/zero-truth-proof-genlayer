import subprocess
import sys
import os

def main():
    print("====================================================")
    print("Starting ZeroTruthProof Contract Verification...")
    print("====================================================\n")
    
    # Resolve the path to tests/test_zero_truth_proof.py relative to the repository root
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    test_file = os.path.join(repo_root, "tests", "test_zero_truth_proof.py")
    
    # Run the test suite using Python's unittest module
    result = subprocess.run([sys.executable, test_file], cwd=repo_root)
    
    if result.returncode == 0:
        print("\n[SUCCESS] Smart contract and local mock test verification completed successfully.")
        sys.exit(0)
    else:
        print("\n[FAILURE] Smart contract execution checks failed.")
        sys.exit(result.returncode)

if __name__ == "__main__":
    main()

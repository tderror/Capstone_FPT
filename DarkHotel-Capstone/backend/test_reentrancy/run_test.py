"""Test RAG V5 with 5 Reentrancy test files"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from smart_rag_system import SmartRAGSystem
from pathlib import Path

def main():
    print("=" * 70)
    print("RAG V5 DAppSCAN - Reentrancy Detection Test")
    print("=" * 70)

    # Initialize RAG
    rag = SmartRAGSystem()
    print(f"\nKB Stats: {rag.get_stats()}\n")

    # Test files
    test_dir = Path(__file__).parent
    test_files = sorted(test_dir.glob("RE_TEST_*.sol"))

    results = []

    for sol_file in test_files:
        print("-" * 70)
        print(f"Testing: {sol_file.name}")
        print("-" * 70)

        code = sol_file.read_text(encoding='utf-8')

        # Detect vulnerabilities
        vulns = rag.detect_vulnerabilities(code)

        # Search similar
        similar = rag.search_similar(code, top_k=3)

        # Result
        detected = "Reentrancy" in vulns
        confidence = vulns.get("Reentrancy", {}).get("confidence", 0)

        print(f"  Detected: {'YES' if detected else 'NO'}")
        print(f"  Confidence: {confidence:.2%}" if detected else "")

        if similar:
            print(f"  Top RAG match: {similar[0]['vulnerability_type']} ({similar[0]['similarity']:.2%})")

        results.append({
            "file": sol_file.name,
            "detected": detected,
            "confidence": confidence,
            "vulns": list(vulns.keys())
        })
        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    detected_count = sum(1 for r in results if r["detected"])
    print(f"Detected: {detected_count}/5 files")
    print(f"Accuracy: {detected_count/5*100:.0f}%")

    print("\nDetails:")
    for r in results:
        status = "PASS" if r["detected"] else "FAIL"
        print(f"  [{status}] {r['file']}: {r['vulns'] if r['vulns'] else 'None detected'}")

if __name__ == "__main__":
    main()

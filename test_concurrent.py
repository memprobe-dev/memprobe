"""Test 5 concurrent ELF uploads against the local dev server."""

import sys
import time
import threading
import urllib.request

SERVER = "http://127.0.0.1:8000"
N = 5


def upload(file_path: str, idx: int, results: list):
    with open(file_path, "rb") as f:
        data = f.read()

    boundary = b"----boundary"
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="firmware.elf"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + data
        + b"\r\n--" + boundary + b"--\r\n"
    )

    req = urllib.request.Request(
        f"{SERVER}/api/analyze",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        method="POST",
    )

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            elapsed = round(time.monotonic() - t0, 1)
            status = resp.status
            results[idx] = f"[{idx+1}] OK ({status}) in {elapsed}s"
    except Exception as e:
        elapsed = round(time.monotonic() - t0, 1)
        results[idx] = f"[{idx+1}] ERROR after {elapsed}s: {e}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_concurrent.py <path/to/firmware.elf>")
        sys.exit(1)

    file_path = sys.argv[1]
    results = [None] * N

    print(f"Launching {N} concurrent uploads of {file_path}...")
    t0 = time.monotonic()

    threads = [threading.Thread(target=upload, args=(file_path, i, results)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    wall = round(time.monotonic() - t0, 1)
    print(f"\nAll done in {wall}s wall time:")
    for r in results:
        print(f"  {r}")


if __name__ == "__main__":
    main()

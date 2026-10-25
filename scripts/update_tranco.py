"""Download the latest Tranco list and derive the allowlist and the benign evaluation set.

- data/tranco_top.csv   ranks 1-10,000      allowlist (step 8e)
- data/eval/benign.txt  ranks 10,001-90,000 benign evaluation set (step 6b); the top
                        10,000 are excluded, because they are allowlisted and would
                        make the false-positive rate look better than it is
- data/eval/tranco_id.txt  list ID, so results can be reproduced

Run weekly: python -m scripts.update_tranco
"""
import io
import urllib.request
import zipfile
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
URL = "https://tranco-list.eu/top-1m.csv.zip"
ID_URL = "https://tranco-list.eu/top-1m-id"
MAX_BYTES = 50 * 1024 * 1024
TOP_N = 10_000
BENIGN_END = 90_000


def fetch(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "PhishFinder/0.1 (research)"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url} is larger than {MAX_BYTES} bytes")
    return data

def main() -> None:
    archive = zipfile.ZipFile(io.BytesIO(fetch(URL, timeout=120)))
    rows = archive.read("top-1m.csv").decode("utf-8").splitlines()[:BENIGN_END]
    list_id = fetch(ID_URL, timeout=30).decode().strip()

    (DATA / "eval").mkdir(parents=True, exist_ok=True)
    (DATA / "tranco_top.csv").write_text("\n".join(rows[:TOP_N]) + "\n", encoding="utf-8")
    benign = [row.split(",", 1)[1] for row in rows[TOP_N:]]
    (DATA / "eval" / "benign.txt").write_text(
        f"# Tranco list {list_id}, ranks {TOP_N + 1}-{BENIGN_END}\n" + "\n".join(benign) + "\n",
        encoding="utf-8")
    (DATA / "eval" / "tranco_id.txt").write_text(list_id + "\n", encoding="utf-8")
    print(f"Tranco list {list_id}: {TOP_N:,} allowlisted, {len(benign):,} benign")

if __name__ == "__main__":
    main()
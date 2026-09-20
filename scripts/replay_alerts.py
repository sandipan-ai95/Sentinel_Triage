#!/usr/bin/env python3
import argparse
import json
import time
from pathlib import Path

import httpx


def load_jsonl(path: Path):
    with path.open('r', encoding='utf-8') as fh:
        for line in fh:
            if not line.strip():
                continue
            yield json.loads(line)


def main():
    parser = argparse.ArgumentParser(description='Replay safe JSONL alerts into the local alert API.')
    parser.add_argument('--path', required=True)
    parser.add_argument('--delay-seconds', type=float, default=0.2)
    parser.add_argument('--base-url', default='http://localhost:8000')
    args = parser.parse_args()

    for event in load_jsonl(Path(args.path)):
        response = httpx.post(f'{args.base_url}/api/alerts', json=event, timeout=10.0)
        print(f"POST {event.get('id')} -> {response.status_code} {response.text[:120]}")
        time.sleep(args.delay_seconds)


if __name__ == '__main__':
    main()

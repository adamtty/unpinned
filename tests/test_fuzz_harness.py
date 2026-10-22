"""Drive the Atheris harness (tests/fuzz_parsers.py) without Atheris, which is Linux-only: every seed in
tests/fuzz-corpus/parsers/ plus seeded random byte mutations of them must satisfy the harness contract."""

import importlib.util
import random
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SEED = 20261022
SPLICE = [
    b"\x00",
    b"\xff",
    b"dex\n035\x00",
    b"-----BEGIN CERTIFICATE-----",
    b"<pin-set>",
    b"</pin-set>",
    b"../",
    b":",
    b"[",
    b"]",
    b"<clinit>",
    b".locals 0\n",
    b"\x30\x82",
]


def _load():
    spec = importlib.util.spec_from_file_location("fuzz_parsers", HERE / "fuzz_parsers.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        op, i = rng.random(), rng.randrange(len(b) + 1)
        if op < 0.3 and len(b) > 1:
            del b[1 + i % (len(b) - 1) : 1 + i % (len(b) - 1) + rng.randint(1, 16)]
        elif op < 0.7:
            b[max(i, 1) : max(i, 1)] = rng.choice(SPLICE)
        elif len(b) > 1:
            b[1 + i % (len(b) - 1)] = rng.randrange(256)
    return bytes(b)


def test_harness_accepts_its_seed_corpus():
    mod = _load()
    seeds = sorted((HERE / "fuzz-corpus" / "parsers").glob("*.seed"))
    assert len(seeds) >= 6
    for p in seeds:
        mod.TestOneInput(p.read_bytes())


@pytest.mark.parametrize("batch", range(4))
def test_harness_survives_random_mutations(batch):
    mod = _load()
    seeds = [p.read_bytes() for p in sorted((HERE / "fuzz-corpus" / "parsers").glob("*.seed"))]
    rng = random.Random(SEED + batch)
    for _ in range(150):
        mod.TestOneInput(_mutate(rng, rng.choice(seeds)))

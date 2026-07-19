"""Offline, deterministic embedding for Stage-2 semantic alignment.

**Honest scope.** :class:`LexicalEmbedder` is a *term-frequency* embedder — a
deterministic, offline **stand-in** for a real sentence-embedding model. It
captures lexical overlap, not deep semantics; a production HMDC plugs a real
sentence-transformer (or a connector-backed embedding model) in behind the same
:class:`Embedder` interface. It is used here so the semantic-alignment *gate*
and its tests run offline and deterministically, without pretending to be a
neural embedding.
"""
from __future__ import annotations

import math
import re
from typing import Protocol, runtime_checkable

#: A minimal stopword set so alignment reflects content words, not glue.
_STOPWORDS: frozenset[str] = frozenset(
    "a an the of to and or is are be for on in it this that with as at by from "
    "we you they i he she them our your its into over under then than".split())


def _tokens(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in _STOPWORDS]


@runtime_checkable
class Embedder(Protocol):
    family: str

    def embed(self, text: str) -> dict[str, float]:
        ...


class LexicalEmbedder:
    """Bag-of-content-words term-frequency vectors (a lexical proxy)."""

    family = "lexical-tf"

    def embed(self, text: str) -> dict[str, float]:
        vec: dict[str, float] = {}
        for tok in _tokens(text):
            vec[tok] = vec.get(tok, 0.0) + 1.0
        return vec


def cosine(a: dict[str, float], b: dict[str, float]) -> float:
    """Cosine similarity of two sparse term vectors, in ``[0, 1]``."""
    if not a or not b:
        return 0.0
    dot = sum(a[t] * b[t] for t in a.keys() & b.keys())
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def information_density(text: str, reference_vocab: set[str]) -> float:
    """Fraction of a candidate's content tokens that appear in the reference.

    The verbosity-bias lever: padding a correct answer with off-topic filler
    lowers this ratio, which the judge uses to *down*-weight verbose answers.
    """
    toks = _tokens(text)
    if not toks:
        return 0.0
    relevant = sum(1 for t in toks if t in reference_vocab)
    return relevant / len(toks)

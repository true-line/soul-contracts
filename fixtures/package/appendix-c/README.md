# Appendix C byte vectors

Start in this directory. The three regular files under `Contents/` are the exact covered inputs. Read them as bytes, with logical mode `0644`. Both JSON files end at the closing brace. The instruction ends with one LF. The test data is in [vectors.json](vectors.json).

1. Hash each file with SHA-256. Compare its length and lowercase hex digest with the corresponding entry in the vector.
2. Sort entries by ascending ASCII path bytes. Each entry contains exactly `mode`, `path` and `sha256`. Serialize the array with RFC 8785.
3. Prefix those bytes with ASCII `SOUL-DEFINITION-EXAMPLE-1` and one LF. Compare with the 376 raw bytes in [preimage.txt](preimage.txt), which ends at the closing bracket. SHA-256 of those bytes is `36a0351bd2ac3db3b091b65c85def71064632889c34215e75a97ae88595ce768`.
4. Resolve fixture references relative to the repository's `fixtures/` directory and read the envelope's `input`. Compare the revision in each unsigned identity and in A's checkpoint with the computed revision. The `sha256:` prefix tags the record reference. An envelope's `canonical_sha256` identifies that record's JCS bytes and is independent of the definition revision.

The checkpoint selects empty durable life and carries A's local epoch zero. The template selection includes definition and source provenance for a new identity. Life transfer selects A's identity and checkpoint with prior placement unresolved. Both are illustrative selections. The recipient can verify definition integrity. Identity authentication remains unverified, restriction freshness unknown, protected-content checking inapplicable and execution unavailable.

Each negative vector starts from a fresh copy of the same inputs and the original expected inventory. Replace or add each listed path using its `mode` and the UTF-8 bytes of its decoded `utf8` string. Check strict manifest parsing first, then attempts to change exclusions, then paths, modes and file digests. The refusal labels identify fixture outcomes. The one-byte change also supplies the revision of the rebuilt inventory for an independent comparison.

Run `python scripts/validate.py` from the repository root to check the schemas, records and vectors together.

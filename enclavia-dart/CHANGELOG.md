# Changelog

## 0.2.0

- First version prepared for pub.dev (adds the required `LICENSE` and
  `CHANGELOG.md`; published archives pin `enclavia-ffi` to the matching
  release tag).
- Tracks the 0.2.0 SDK release: transparent reconnect with re-verified
  attestation, and the shared 32 KiB vsock write chunking in
  `enclavia-protocol`.

## 0.1.0

- Initial release: UniFFI-based Dart bindings for the enclavia client SDK
  (`Client.connect` + `Client.fetch` over an attested Noise tunnel), with
  the native library built locally via Dart Native Assets.

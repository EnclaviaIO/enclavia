import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:enclavia_dart/enclavia_dart.dart';

/// Run with: `dart run example/main.dart`
///
/// Prerequisites:
///  * Rust toolchain available for Native Assets builds.
///  * If you update `enclavia-ffi`, regenerate bindings with
///    `bash ./scripts/generate_bindings.sh`.
///  * A running enclave and its PCR measurements
///    (`enclavia enclave status`), passed via env vars below.
Uint8List hexDecode(String hex) {
  final bytes = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

Future<void> main() async {
  final url = Platform.environment['ENCLAVIA_URL'];
  if (url == null) {
    stdout.writeln(
      'Set ENCLAVIA_URL (wss://<id>.enclaves.<env>.enclavia.io), '
      'ENCLAVIA_PCR0/1/2 (hex, from `enclavia enclave status`), and '
      'optionally ENCLAVIA_DEBUG_MODE=1 for a debug enclave.',
    );
    return;
  }

  final pcrs = Pcrs(
    pcr0: hexDecode(Platform.environment['ENCLAVIA_PCR0'] ?? ''),
    pcr1: hexDecode(Platform.environment['ENCLAVIA_PCR1'] ?? ''),
    pcr2: hexDecode(Platform.environment['ENCLAVIA_PCR2'] ?? ''),
  );
  final debugMode = Platform.environment['ENCLAVIA_DEBUG_MODE'] == '1';

  final client = await Client.connect(
    url: url,
    pcrs: pcrs,
    options: ConnectOptions(debugMode: debugMode, trustUpgrades: null),
  );
  stdout.writeln('Connected and attestation verified.');

  final response = await client.fetch(
    method: 'GET',
    path: '/health',
    options: null,
  );
  stdout.writeln('GET /health -> ${response.status}');
  stdout.writeln(utf8.decode(response.body));
}

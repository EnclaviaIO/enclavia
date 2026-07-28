// Reconnect smoke test: the Dart bindings against a LOCAL mock enclave
// that drops the connection after every answered request, so every fetch
// past the first forces a transparent reconnect (full Noise + attestation
// re-verify). Mirrors `enclavia-wasm/reconnect-smoke.mjs` exactly, just
// through `enclavia_dart` instead of the wasm bindings. Needs NO deployed
// enclave.
//
// Start the mock first (it prints its port):
//   cargo run --example reconnect_mock_server -p enclavia
// Then: dart run reconnect_smoke.dart <mock-port>
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:enclavia_dart/enclavia_dart.dart';

Uint8List hexRepeat(int seedByte, int count) {
  final bytes = Uint8List(count);
  bytes.fillRange(0, count, seedByte);
  return bytes;
}

Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln('usage: dart run reconnect_smoke.dart <mock-port>');
    exit(2);
  }
  final url = 'ws://127.0.0.1:${args[0]}';

  // The mock attests with FakeAttestation::with_seed(0x11): pcrN is the
  // byte (seed + N) repeated 48 times.
  final pcrs = Pcrs(
    pcr0: hexRepeat(0x11, 48),
    pcr1: hexRepeat(0x12, 48),
    pcr2: hexRepeat(0x13, 48),
  );

  // 1. Wrong PCRs must be refused: reconnect logic never weakens the
  // attestation gate, including on the very first connect.
  try {
    await Client.connect(
      url: url,
      pcrs: Pcrs(pcr0: hexRepeat(0x00, 48), pcr1: pcrs.pcr1, pcr2: pcrs.pcr2),
      options: ConnectOptions(debugMode: true, trustUpgrades: null),
    );
    throw Exception('connect with wrong PCR0 should have failed!');
  } on EnclaviaException catch (e) {
    final message = e is ClientEnclaviaException ? e.message : e.toString();
    if (!RegExp(r'PCR|attestation', caseSensitive: false).hasMatch(message)) {
      rethrow;
    }
    stdout.writeln('OK: wrong PCR0 refused: ${message.substring(0, message.length > 70 ? 70 : message.length)}');
  }

  // 2. Connect with the right PCRs. NOTE: the failed connect above
  // consumed one mock connection, and the mock drops after ONE answered
  // request, so every fetch below lands on its own fresh connection.
  final client = await Client.connect(
    url: url,
    pcrs: pcrs,
    options: ConnectOptions(debugMode: true, trustUpgrades: null),
  );
  stdout.writeln('OK: connected, attestation verified');

  // 3. First request on the live channel.
  final r1 = await client.fetch(method: 'GET', path: '/one', options: null);
  final b1 = utf8.decode(r1.body);
  if (r1.status != 200) throw Exception('fetch 1 -> ${r1.status}');
  stdout.writeln('OK: fetch 1 -> ${r1.status} "$b1"');

  // The server dropped the channel after answering. Give the client's
  // background reader a beat to observe the close event.
  await Future.delayed(const Duration(milliseconds: 300));

  // 4. Second request MUST transparently reconnect + re-attest.
  final r2 = await client.fetch(method: 'GET', path: '/two', options: null);
  final b2 = utf8.decode(r2.body);
  if (r2.status != 200) {
    throw Exception('fetch 2 (post-drop) -> ${r2.status}');
  }
  stdout.writeln(
    'OK: fetch 2 after server drop -> ${r2.status} "$b2" (transparent reconnect)',
  );

  // 5. And again, to prove it is repeatable, not a one-shot.
  await Future.delayed(const Duration(milliseconds: 300));
  final r3 = await client.fetch(method: 'GET', path: '/three', options: null);
  final b3 = utf8.decode(r3.body);
  if (r3.status != 200) throw Exception('fetch 3 -> ${r3.status}');
  stdout.writeln('OK: fetch 3 after another drop -> ${r3.status} "$b3"');

  // 6. The mock stamps each connection number into the body: the three
  // fetches must have come over three DISTINCT connections (the
  // reconnects really happened; the responses were not replays).
  final connPattern = RegExp(r'^conn-(\d+)$');
  final conns = [b1, b2, b3].map((b) {
    final m = connPattern.firstMatch(b);
    if (m == null) throw Exception('unexpected body "$b"');
    return int.parse(m.group(1)!);
  }).toList();
  final distinct = conns.toSet();
  if (distinct.length != 3 || !(conns[0] < conns[1] && conns[1] < conns[2])) {
    throw Exception('expected 3 distinct increasing connections, got $conns');
  }
  stdout.writeln(
    'OK: three requests served over three distinct connections: ${conns.join(', ')}',
  );

  client.dispose();
  stdout.writeln('DART RECONNECT SMOKE TEST PASSED');
}

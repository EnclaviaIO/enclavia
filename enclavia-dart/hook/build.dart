import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

Future<void> main(List<String> args) async {
  await build(args, (input, output) async {
    final cargoConfigPath = input.packageRoot
        .resolve('native/.cargo/config.toml')
        .toFilePath();

    // `ConnectOptions.debugMode` validates a QEMU enclave's attestation
    // without the AWS Nitro certificate chain, so any well-formed document
    // passes. That path is compiled in only when the root package asks for a
    // development build in its pubspec:
    //
    //   hooks:
    //     user_defines:
    //       enclavia_dart:
    //         dangerous_skip_chain: true
    //
    // Every other build refuses debug-mode connections.
    final skipChain = input.userDefines['dangerous_skip_chain'] == true;

    // Native Assets invokes Cargo from the package root, so pass the crate-local
    // config explicitly instead of relying on Cargo's working-directory lookup.
    await RustBuilder(
      assetName: 'uniffi:enclavia_dart_ffi',
      features: [if (skipChain) 'dangerous-skip-chain'],
      extraCargoBuildArgs: ['--config', cargoConfigPath],
    ).run(input: input, output: output);
  });
}

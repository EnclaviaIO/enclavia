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
    // Every other build refuses debug-mode connections. Any value other than
    // a YAML boolean (for example the string "true") fails the build rather
    // than silently producing the production flavour.
    final skipChainDefine = input.userDefines['dangerous_skip_chain'];
    if (skipChainDefine != null && skipChainDefine is! bool) {
      throw ArgumentError.value(
        skipChainDefine,
        'dangerous_skip_chain',
        'the enclavia_dart user-define must be a boolean (true or false)',
      );
    }
    final skipChain = skipChainDefine == true;

    // Native Assets invokes Cargo from the package root, so pass the crate-local
    // config explicitly instead of relying on Cargo's working-directory lookup.
    await RustBuilder(
      assetName: 'uniffi:enclavia_dart_ffi',
      features: [if (skipChain) 'dangerous-skip-chain'],
      extraCargoBuildArgs: ['--config', cargoConfigPath],
    ).run(input: input, output: output);
  });
}

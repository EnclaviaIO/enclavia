library enclavia_dart;

import "dart:async";
import "dart:convert";
import "dart:ffi";
import "dart:io" show Platform, File, Directory;
import "dart:isolate";
import "dart:typed_data";
import "package:ffi/ffi.dart";

class ConnectOptions {
  final bool? debugMode;
  final TrustUpgrades? trustUpgrades;
  ConnectOptions({this.debugMode, this.trustUpgrades});
}

class FfiConverterConnectOptions {
  static ConnectOptions lift(RustBuffer buf) {
    return FfiConverterConnectOptions.read(buf.asUint8List()).value;
  }

  static LiftRetVal<ConnectOptions> read(Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    final debugMode_lifted = FfiConverterOptionalBool.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final debugMode = debugMode_lifted.value;
    new_offset += debugMode_lifted.bytesRead;
    final trustUpgrades_lifted = FfiConverterOptionalTrustUpgrades.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final trustUpgrades = trustUpgrades_lifted.value;
    new_offset += trustUpgrades_lifted.bytesRead;
    return LiftRetVal(
      ConnectOptions(debugMode: debugMode, trustUpgrades: trustUpgrades),
      new_offset - buf.offsetInBytes,
    );
  }

  static RustBuffer lower(ConnectOptions value) {
    final total_length =
        FfiConverterOptionalBool.allocationSize(value.debugMode) +
        FfiConverterOptionalTrustUpgrades.allocationSize(value.trustUpgrades) +
        0;
    final buf = Uint8List(total_length);
    write(value, buf);
    return toRustBuffer(buf);
  }

  static int write(ConnectOptions value, Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    new_offset += FfiConverterOptionalBool.write(
      value.debugMode,
      Uint8List.view(buf.buffer, new_offset),
    );
    new_offset += FfiConverterOptionalTrustUpgrades.write(
      value.trustUpgrades,
      Uint8List.view(buf.buffer, new_offset),
    );
    return new_offset - buf.offsetInBytes;
  }

  static int allocationSize(ConnectOptions value) {
    return FfiConverterOptionalBool.allocationSize(value.debugMode) +
        FfiConverterOptionalTrustUpgrades.allocationSize(value.trustUpgrades) +
        0;
  }
}

class FetchOptions {
  final List<Header>? headers;
  final Uint8List? body;
  FetchOptions({this.headers, this.body});
}

class FfiConverterFetchOptions {
  static FetchOptions lift(RustBuffer buf) {
    return FfiConverterFetchOptions.read(buf.asUint8List()).value;
  }

  static LiftRetVal<FetchOptions> read(Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    final headers_lifted = FfiConverterOptionalSequenceHeader.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final headers = headers_lifted.value;
    new_offset += headers_lifted.bytesRead;
    final body_lifted = FfiConverterOptionalUint8List.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final body = body_lifted.value;
    new_offset += body_lifted.bytesRead;
    return LiftRetVal(
      FetchOptions(headers: headers, body: body),
      new_offset - buf.offsetInBytes,
    );
  }

  static RustBuffer lower(FetchOptions value) {
    final total_length =
        FfiConverterOptionalSequenceHeader.allocationSize(value.headers) +
        FfiConverterOptionalUint8List.allocationSize(value.body) +
        0;
    final buf = Uint8List(total_length);
    write(value, buf);
    return toRustBuffer(buf);
  }

  static int write(FetchOptions value, Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    new_offset += FfiConverterOptionalSequenceHeader.write(
      value.headers,
      Uint8List.view(buf.buffer, new_offset),
    );
    new_offset += FfiConverterOptionalUint8List.write(
      value.body,
      Uint8List.view(buf.buffer, new_offset),
    );
    return new_offset - buf.offsetInBytes;
  }

  static int allocationSize(FetchOptions value) {
    return FfiConverterOptionalSequenceHeader.allocationSize(value.headers) +
        FfiConverterOptionalUint8List.allocationSize(value.body) +
        0;
  }
}

class FetchResponse {
  final int status;
  final List<Header> headers;
  final Uint8List body;
  FetchResponse({
    required this.status,
    required this.headers,
    required this.body,
  });
}

class FfiConverterFetchResponse {
  static FetchResponse lift(RustBuffer buf) {
    return FfiConverterFetchResponse.read(buf.asUint8List()).value;
  }

  static LiftRetVal<FetchResponse> read(Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    final status_lifted = FfiConverterUInt16.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final status = status_lifted.value;
    new_offset += status_lifted.bytesRead;
    final headers_lifted = FfiConverterSequenceHeader.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final headers = headers_lifted.value;
    new_offset += headers_lifted.bytesRead;
    final body_lifted = FfiConverterUint8List.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final body = body_lifted.value;
    new_offset += body_lifted.bytesRead;
    return LiftRetVal(
      FetchResponse(status: status, headers: headers, body: body),
      new_offset - buf.offsetInBytes,
    );
  }

  static RustBuffer lower(FetchResponse value) {
    final total_length =
        FfiConverterUInt16.allocationSize(value.status) +
        FfiConverterSequenceHeader.allocationSize(value.headers) +
        FfiConverterUint8List.allocationSize(value.body) +
        0;
    final buf = Uint8List(total_length);
    write(value, buf);
    return toRustBuffer(buf);
  }

  static int write(FetchResponse value, Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    new_offset += FfiConverterUInt16.write(
      value.status,
      Uint8List.view(buf.buffer, new_offset),
    );
    new_offset += FfiConverterSequenceHeader.write(
      value.headers,
      Uint8List.view(buf.buffer, new_offset),
    );
    new_offset += FfiConverterUint8List.write(
      value.body,
      Uint8List.view(buf.buffer, new_offset),
    );
    return new_offset - buf.offsetInBytes;
  }

  static int allocationSize(FetchResponse value) {
    return FfiConverterUInt16.allocationSize(value.status) +
        FfiConverterSequenceHeader.allocationSize(value.headers) +
        FfiConverterUint8List.allocationSize(value.body) +
        0;
  }
}

class Header {
  final String name;
  final String value;
  Header({required this.name, required this.value});
}

class FfiConverterHeader {
  static Header lift(RustBuffer buf) {
    return FfiConverterHeader.read(buf.asUint8List()).value;
  }

  static LiftRetVal<Header> read(Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    final name_lifted = FfiConverterString.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final name = name_lifted.value;
    new_offset += name_lifted.bytesRead;
    final value_lifted = FfiConverterString.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final value = value_lifted.value;
    new_offset += value_lifted.bytesRead;
    return LiftRetVal(
      Header(name: name, value: value),
      new_offset - buf.offsetInBytes,
    );
  }

  static RustBuffer lower(Header value) {
    final total_length =
        FfiConverterString.allocationSize(value.name) +
        FfiConverterString.allocationSize(value.value) +
        0;
    final buf = Uint8List(total_length);
    write(value, buf);
    return toRustBuffer(buf);
  }

  static int write(Header value, Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    new_offset += FfiConverterString.write(
      value.name,
      Uint8List.view(buf.buffer, new_offset),
    );
    new_offset += FfiConverterString.write(
      value.value,
      Uint8List.view(buf.buffer, new_offset),
    );
    return new_offset - buf.offsetInBytes;
  }

  static int allocationSize(Header value) {
    return FfiConverterString.allocationSize(value.name) +
        FfiConverterString.allocationSize(value.value) +
        0;
  }
}

class Pcrs {
  final Uint8List pcr0;
  final Uint8List pcr1;
  final Uint8List pcr2;
  Pcrs({required this.pcr0, required this.pcr1, required this.pcr2});
}

class FfiConverterPcrs {
  static Pcrs lift(RustBuffer buf) {
    return FfiConverterPcrs.read(buf.asUint8List()).value;
  }

  static LiftRetVal<Pcrs> read(Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    final pcr0_lifted = FfiConverterUint8List.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final pcr0 = pcr0_lifted.value;
    new_offset += pcr0_lifted.bytesRead;
    final pcr1_lifted = FfiConverterUint8List.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final pcr1 = pcr1_lifted.value;
    new_offset += pcr1_lifted.bytesRead;
    final pcr2_lifted = FfiConverterUint8List.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final pcr2 = pcr2_lifted.value;
    new_offset += pcr2_lifted.bytesRead;
    return LiftRetVal(
      Pcrs(pcr0: pcr0, pcr1: pcr1, pcr2: pcr2),
      new_offset - buf.offsetInBytes,
    );
  }

  static RustBuffer lower(Pcrs value) {
    final total_length =
        FfiConverterUint8List.allocationSize(value.pcr0) +
        FfiConverterUint8List.allocationSize(value.pcr1) +
        FfiConverterUint8List.allocationSize(value.pcr2) +
        0;
    final buf = Uint8List(total_length);
    write(value, buf);
    return toRustBuffer(buf);
  }

  static int write(Pcrs value, Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    new_offset += FfiConverterUint8List.write(
      value.pcr0,
      Uint8List.view(buf.buffer, new_offset),
    );
    new_offset += FfiConverterUint8List.write(
      value.pcr1,
      Uint8List.view(buf.buffer, new_offset),
    );
    new_offset += FfiConverterUint8List.write(
      value.pcr2,
      Uint8List.view(buf.buffer, new_offset),
    );
    return new_offset - buf.offsetInBytes;
  }

  static int allocationSize(Pcrs value) {
    return FfiConverterUint8List.allocationSize(value.pcr0) +
        FfiConverterUint8List.allocationSize(value.pcr1) +
        FfiConverterUint8List.allocationSize(value.pcr2) +
        0;
  }
}

class TrustUpgrades {
  final String backendUrl;
  final String enclaveId;
  TrustUpgrades({required this.backendUrl, required this.enclaveId});
}

class FfiConverterTrustUpgrades {
  static TrustUpgrades lift(RustBuffer buf) {
    return FfiConverterTrustUpgrades.read(buf.asUint8List()).value;
  }

  static LiftRetVal<TrustUpgrades> read(Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    final backendUrl_lifted = FfiConverterString.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final backendUrl = backendUrl_lifted.value;
    new_offset += backendUrl_lifted.bytesRead;
    final enclaveId_lifted = FfiConverterString.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final enclaveId = enclaveId_lifted.value;
    new_offset += enclaveId_lifted.bytesRead;
    return LiftRetVal(
      TrustUpgrades(backendUrl: backendUrl, enclaveId: enclaveId),
      new_offset - buf.offsetInBytes,
    );
  }

  static RustBuffer lower(TrustUpgrades value) {
    final total_length =
        FfiConverterString.allocationSize(value.backendUrl) +
        FfiConverterString.allocationSize(value.enclaveId) +
        0;
    final buf = Uint8List(total_length);
    write(value, buf);
    return toRustBuffer(buf);
  }

  static int write(TrustUpgrades value, Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    new_offset += FfiConverterString.write(
      value.backendUrl,
      Uint8List.view(buf.buffer, new_offset),
    );
    new_offset += FfiConverterString.write(
      value.enclaveId,
      Uint8List.view(buf.buffer, new_offset),
    );
    return new_offset - buf.offsetInBytes;
  }

  static int allocationSize(TrustUpgrades value) {
    return FfiConverterString.allocationSize(value.backendUrl) +
        FfiConverterString.allocationSize(value.enclaveId) +
        0;
  }
}

abstract class EnclaviaException implements Exception {
  RustBuffer lower();
  int allocationSize();
  int write(Uint8List buf);
}

class FfiConverterEnclaviaException {
  static EnclaviaException lift(RustBuffer buffer) {
    return FfiConverterEnclaviaException.read(buffer.asUint8List()).value;
  }

  static LiftRetVal<EnclaviaException> read(Uint8List buf) {
    final index = buf.buffer.asByteData(buf.offsetInBytes).getInt32(0);
    final subview = Uint8List.view(buf.buffer, buf.offsetInBytes + 4);
    switch (index) {
      case 1:
        final lifted = ClientEnclaviaException.read(subview);
        return LiftRetVal<EnclaviaException>(
          lifted.value,
          lifted.bytesRead - subview.offsetInBytes + 4,
        );
      case 2:
        final lifted = InvalidMethodEnclaviaException.read(subview);
        return LiftRetVal<EnclaviaException>(
          lifted.value,
          lifted.bytesRead - subview.offsetInBytes + 4,
        );
      case 3:
        final lifted = InvalidEnclaveIdEnclaviaException.read(subview);
        return LiftRetVal<EnclaviaException>(
          lifted.value,
          lifted.bytesRead - subview.offsetInBytes + 4,
        );
      default:
        throw UniffiInternalError(
          UniffiInternalError.unexpectedEnumCase,
          "Unable to determine enum variant",
        );
    }
  }

  static RustBuffer lower(EnclaviaException value) {
    return value.lower();
  }

  static int allocationSize(EnclaviaException value) {
    return value.allocationSize();
  }

  static int write(EnclaviaException value, Uint8List buf) {
    return value.write(buf) - buf.offsetInBytes;
  }
}

class ClientEnclaviaException extends EnclaviaException {
  final String message;
  final bool retryable;
  ClientEnclaviaException({
    required String this.message,
    required bool this.retryable,
  });
  ClientEnclaviaException._(String this.message, bool this.retryable);
  static LiftRetVal<ClientEnclaviaException> read(Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    final message_lifted = FfiConverterString.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final message = message_lifted.value;
    new_offset += message_lifted.bytesRead;
    final retryable_lifted = FfiConverterBool.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final retryable = retryable_lifted.value;
    new_offset += retryable_lifted.bytesRead;
    return LiftRetVal(
      ClientEnclaviaException._(message, retryable),
      new_offset,
    );
  }

  @override
  RustBuffer lower() {
    final buf = Uint8List(allocationSize());
    write(buf);
    return toRustBuffer(buf);
  }

  @override
  int allocationSize() {
    return FfiConverterString.allocationSize(message) +
        FfiConverterBool.allocationSize(retryable) +
        4;
  }

  @override
  int write(Uint8List buf) {
    buf.buffer.asByteData(buf.offsetInBytes).setInt32(0, 1);
    int new_offset = buf.offsetInBytes + 4;
    new_offset += FfiConverterString.write(
      message,
      Uint8List.view(buf.buffer, new_offset),
    );
    new_offset += FfiConverterBool.write(
      retryable,
      Uint8List.view(buf.buffer, new_offset),
    );
    return new_offset;
  }

  @override
  String toString() {
    return "ClientEnclaviaException($message, $retryable)";
  }
}

class InvalidMethodEnclaviaException extends EnclaviaException {
  final String v0;
  InvalidMethodEnclaviaException(String this.v0);
  InvalidMethodEnclaviaException._(String this.v0);
  static LiftRetVal<InvalidMethodEnclaviaException> read(Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    final v0_lifted = FfiConverterString.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final v0 = v0_lifted.value;
    new_offset += v0_lifted.bytesRead;
    return LiftRetVal(InvalidMethodEnclaviaException._(v0), new_offset);
  }

  @override
  RustBuffer lower() {
    final buf = Uint8List(allocationSize());
    write(buf);
    return toRustBuffer(buf);
  }

  @override
  int allocationSize() {
    return FfiConverterString.allocationSize(v0) + 4;
  }

  @override
  int write(Uint8List buf) {
    buf.buffer.asByteData(buf.offsetInBytes).setInt32(0, 2);
    int new_offset = buf.offsetInBytes + 4;
    new_offset += FfiConverterString.write(
      v0,
      Uint8List.view(buf.buffer, new_offset),
    );
    return new_offset;
  }

  @override
  String toString() {
    return "InvalidMethodEnclaviaException($v0)";
  }
}

class InvalidEnclaveIdEnclaviaException extends EnclaviaException {
  final String v0;
  InvalidEnclaveIdEnclaviaException(String this.v0);
  InvalidEnclaveIdEnclaviaException._(String this.v0);
  static LiftRetVal<InvalidEnclaveIdEnclaviaException> read(Uint8List buf) {
    int new_offset = buf.offsetInBytes;
    final v0_lifted = FfiConverterString.read(
      Uint8List.view(buf.buffer, new_offset),
    );
    final v0 = v0_lifted.value;
    new_offset += v0_lifted.bytesRead;
    return LiftRetVal(InvalidEnclaveIdEnclaviaException._(v0), new_offset);
  }

  @override
  RustBuffer lower() {
    final buf = Uint8List(allocationSize());
    write(buf);
    return toRustBuffer(buf);
  }

  @override
  int allocationSize() {
    return FfiConverterString.allocationSize(v0) + 4;
  }

  @override
  int write(Uint8List buf) {
    buf.buffer.asByteData(buf.offsetInBytes).setInt32(0, 3);
    int new_offset = buf.offsetInBytes + 4;
    new_offset += FfiConverterString.write(
      v0,
      Uint8List.view(buf.buffer, new_offset),
    );
    return new_offset;
  }

  @override
  String toString() {
    return "InvalidEnclaveIdEnclaviaException($v0)";
  }
}

class EnclaviaExceptionErrorHandler extends UniffiRustCallStatusErrorHandler {
  @override
  Exception lift(RustBuffer errorBuf) {
    return FfiConverterEnclaviaException.lift(errorBuf);
  }
}

final EnclaviaExceptionErrorHandler enclaviaExceptionErrorHandler =
    EnclaviaExceptionErrorHandler();

abstract class ClientInterface {
  Future<FetchResponse> fetch({
    required String method,
    required String path,
    required FetchOptions? options,
  });
}

final _ClientFinalizer = Finalizer<Pointer<Void>>((ptr) {
  rustCall((status) => uniffi_enclavia_ffi_fn_free_client(ptr, status));
});

class Client implements ClientInterface {
  late final Pointer<Void> _ptr;
  Client._(this._ptr) {
    _ClientFinalizer.attach(this, _ptr, detach: this);
  }
  static Future<Client> connect({
    required String url,
    required Pcrs pcrs,
    required ConnectOptions? options,
  }) {
    return uniffiRustCallAsync(
      () => uniffi_enclavia_ffi_fn_constructor_client_connect(
        FfiConverterString.lower(url),
        FfiConverterPcrs.lower(pcrs),
        FfiConverterOptionalConnectOptions.lower(options),
      ),
      ffi_enclavia_ffi_rust_future_poll_u64,
      ffi_enclavia_ffi_rust_future_complete_u64,
      ffi_enclavia_ffi_rust_future_free_u64,
      (int handle) => Client._(Pointer<Void>.fromAddress(handle)),
      enclaviaExceptionErrorHandler,
    );
  }

  factory Client.lift(Pointer<Void> ptr) {
    return Client._(ptr);
  }
  static Pointer<Void> lower(Client value) {
    return value.uniffiClonePointer();
  }

  Pointer<Void> uniffiClonePointer() {
    return rustCall(
      (status) => uniffi_enclavia_ffi_fn_clone_client(_ptr, status),
    );
  }

  static int allocationSize(Client value) {
    return 8;
  }

  static LiftRetVal<Client> read(Uint8List buf) {
    final handle = buf.buffer.asByteData(buf.offsetInBytes).getInt64(0);
    final pointer = Pointer<Void>.fromAddress(handle);
    return LiftRetVal(Client.lift(pointer), 8);
  }

  static int write(Client value, Uint8List buf) {
    final handle = lower(value);
    buf.buffer.asByteData(buf.offsetInBytes).setInt64(0, handle.address);
    return 8;
  }

  void dispose() {
    _ClientFinalizer.detach(this);
    rustCall((status) => uniffi_enclavia_ffi_fn_free_client(_ptr, status));
  }

  Future<FetchResponse> fetch({
    required String method,
    required String path,
    required FetchOptions? options,
  }) {
    return uniffiRustCallAsync(
      () => uniffi_enclavia_ffi_fn_method_client_fetch(
        uniffiClonePointer(),
        FfiConverterString.lower(method),
        FfiConverterString.lower(path),
        FfiConverterOptionalFetchOptions.lower(options),
      ),
      ffi_enclavia_ffi_rust_future_poll_rust_buffer,
      ffi_enclavia_ffi_rust_future_complete_rust_buffer,
      ffi_enclavia_ffi_rust_future_free_rust_buffer,
      FfiConverterFetchResponse.lift,
      enclaviaExceptionErrorHandler,
    );
  }
}

class UniffiInternalError implements Exception {
  static const int bufferOverflow = 0;
  static const int incompleteData = 1;
  static const int unexpectedOptionalTag = 2;
  static const int unexpectedEnumCase = 3;
  static const int unexpectedNullPointer = 4;
  static const int unexpectedRustCallStatusCode = 5;
  static const int unexpectedRustCallError = 6;
  static const int unexpectedStaleHandle = 7;
  static const int rustPanic = 8;
  final int errorCode;
  final String? panicMessage;
  const UniffiInternalError(this.errorCode, this.panicMessage);
  static UniffiInternalError panicked(String message) {
    return UniffiInternalError(rustPanic, message);
  }

  @override
  String toString() {
    switch (errorCode) {
      case bufferOverflow:
        return "UniFfi::BufferOverflow";
      case incompleteData:
        return "UniFfi::IncompleteData";
      case unexpectedOptionalTag:
        return "UniFfi::UnexpectedOptionalTag";
      case unexpectedEnumCase:
        return "UniFfi::UnexpectedEnumCase";
      case unexpectedNullPointer:
        return "UniFfi::UnexpectedNullPointer";
      case unexpectedRustCallStatusCode:
        return "UniFfi::UnexpectedRustCallStatusCode";
      case unexpectedRustCallError:
        return "UniFfi::UnexpectedRustCallError";
      case unexpectedStaleHandle:
        return "UniFfi::UnexpectedStaleHandle";
      case rustPanic:
        return "UniFfi::rustPanic: $panicMessage";
      default:
        return "UniFfi::UnknownError: $errorCode";
    }
  }
}

const int CALL_SUCCESS = 0;
const int CALL_ERROR = 1;
const int CALL_UNEXPECTED_ERROR = 2;

final class RustCallStatus extends Struct {
  @Int8()
  external int code;
  external RustBuffer errorBuf;
}

void checkCallStatus(
  UniffiRustCallStatusErrorHandler errorHandler,
  Pointer<RustCallStatus> status,
) {
  if (status.ref.code == CALL_SUCCESS) {
    return;
  } else if (status.ref.code == CALL_ERROR) {
    throw errorHandler.lift(status.ref.errorBuf);
  } else if (status.ref.code == CALL_UNEXPECTED_ERROR) {
    if (status.ref.errorBuf.len > 0) {
      throw UniffiInternalError.panicked(
        FfiConverterString.lift(status.ref.errorBuf),
      );
    } else {
      throw UniffiInternalError.panicked("Rust panic");
    }
  } else {
    throw UniffiInternalError.panicked(
      "Unexpected RustCallStatus code: \${status.ref.code}",
    );
  }
}

T rustCall<T>(
  T Function(Pointer<RustCallStatus>) callback, [
  UniffiRustCallStatusErrorHandler? errorHandler,
]) {
  final status = calloc<RustCallStatus>();
  try {
    final result = callback(status);
    checkCallStatus(errorHandler ?? NullRustCallStatusErrorHandler(), status);
    return result;
  } finally {
    calloc.free(status);
  }
}

T rustCallWithLifter<T, F>(
  F Function(Pointer<RustCallStatus>) ffiCall,
  T Function(F) lifter, [
  UniffiRustCallStatusErrorHandler? errorHandler,
]) {
  final status = calloc<RustCallStatus>();
  try {
    final rawResult = ffiCall(status);
    checkCallStatus(errorHandler ?? NullRustCallStatusErrorHandler(), status);
    return lifter(rawResult);
  } finally {
    calloc.free(status);
  }
}

class NullRustCallStatusErrorHandler extends UniffiRustCallStatusErrorHandler {
  @override
  Exception lift(RustBuffer errorBuf) {
    errorBuf.free();
    return UniffiInternalError.panicked("Unexpected CALL_ERROR");
  }
}

abstract class UniffiRustCallStatusErrorHandler {
  Exception lift(RustBuffer errorBuf);
}

final class RustBuffer extends Struct {
  @Uint64()
  external int capacity;
  @Uint64()
  external int len;
  external Pointer<Uint8> data;
  static RustBuffer alloc(int size) {
    return rustCall(
      (status) => ffi_enclavia_ffi_rustbuffer_alloc(size, status),
    );
  }

  static RustBuffer fromBytes(ForeignBytes bytes) {
    return rustCall(
      (status) => ffi_enclavia_ffi_rustbuffer_from_bytes(bytes, status),
    );
  }

  void free() {
    rustCall((status) => ffi_enclavia_ffi_rustbuffer_free(this, status));
  }

  RustBuffer reserve(int additionalCapacity) {
    return rustCall(
      (status) =>
          ffi_enclavia_ffi_rustbuffer_reserve(this, additionalCapacity, status),
    );
  }

  Uint8List asUint8List() {
    final dataList = data.asTypedList(len);
    final byteData = ByteData.sublistView(dataList);
    return Uint8List.view(byteData.buffer);
  }

  @override
  String toString() {
    return "RustBuffer{capacity: \$capacity, len: \$len, data: \$data}";
  }
}

RustBuffer toRustBuffer(Uint8List data) {
  final length = data.length;
  final Pointer<Uint8> frameData = calloc<Uint8>(length);
  final pointerList = frameData.asTypedList(length);
  pointerList.setAll(0, data);
  final bytes = calloc<ForeignBytes>();
  bytes.ref.len = length;
  bytes.ref.data = frameData;
  return RustBuffer.fromBytes(bytes.ref);
}

final class ForeignBytes extends Struct {
  @Int32()
  external int len;
  external Pointer<Uint8> data;
  void free() {
    calloc.free(data);
  }
}

class LiftRetVal<T> {
  final T value;
  final int bytesRead;
  const LiftRetVal(this.value, this.bytesRead);
  LiftRetVal<T> copyWithOffset(int offset) {
    return LiftRetVal(value, bytesRead + offset);
  }
}

abstract class FfiConverter<D, F> {
  const FfiConverter();
  D lift(F value);
  F lower(D value);
  D read(ByteData buffer, int offset);
  void write(D value, ByteData buffer, int offset);
  int size(D value);
}

mixin FfiConverterPrimitive<T> on FfiConverter<T, T> {
  @override
  T lift(T value) => value;
  @override
  T lower(T value) => value;
}
Uint8List createUint8ListFromInt(int value) {
  int length = value.bitLength ~/ 8 + 1;
  if (length != 4 && length != 8) {
    length = (value < 0x100000000) ? 4 : 8;
  }
  Uint8List uint8List = Uint8List(length);
  for (int i = length - 1; i >= 0; i--) {
    uint8List[i] = value & 0xFF;
    value >>= 8;
  }
  return uint8List;
}

class FfiConverterBool {
  static bool lift(int value) {
    return value == 1;
  }

  static int lower(bool value) {
    return value ? 1 : 0;
  }

  static LiftRetVal<bool> read(Uint8List buf) {
    return LiftRetVal(FfiConverterBool.lift(buf.first), 1);
  }

  static RustBuffer lowerIntoRustBuffer(bool value) {
    return toRustBuffer(Uint8List.fromList([FfiConverterBool.lower(value)]));
  }

  static int allocationSize([bool value = false]) {
    return 1;
  }

  static int write(bool value, Uint8List buf) {
    buf.setAll(0, [value ? 1 : 0]);
    return allocationSize();
  }
}

class FfiConverterOptionalBool {
  static bool? lift(RustBuffer buf) {
    return FfiConverterOptionalBool.read(buf.asUint8List()).value;
  }

  static LiftRetVal<bool?> read(Uint8List buf) {
    if (ByteData.view(buf.buffer, buf.offsetInBytes).getInt8(0) == 0) {
      return LiftRetVal(null, 1);
    }
    final result = FfiConverterBool.read(
      Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
    );
    return LiftRetVal<bool?>(result.value, result.bytesRead + 1);
  }

  static int allocationSize([bool? value]) {
    if (value == null) {
      return 1;
    }
    return FfiConverterBool.allocationSize(value) + 1;
  }

  static RustBuffer lower(bool? value) {
    if (value == null) {
      return toRustBuffer(Uint8List.fromList([0]));
    }
    final length = FfiConverterOptionalBool.allocationSize(value);
    final Pointer<Uint8> frameData = calloc<Uint8>(length);
    final buf = frameData.asTypedList(length);
    FfiConverterOptionalBool.write(value, buf);
    final bytes = calloc<ForeignBytes>();
    bytes.ref.len = length;
    bytes.ref.data = frameData;
    return RustBuffer.fromBytes(bytes.ref);
  }

  static int write(bool? value, Uint8List buf) {
    if (value == null) {
      buf[0] = 0;
      return 1;
    }
    buf[0] = 1;
    return FfiConverterBool.write(
          value,
          Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
        ) +
        1;
  }
}

class FfiConverterOptionalConnectOptions {
  static ConnectOptions? lift(RustBuffer buf) {
    return FfiConverterOptionalConnectOptions.read(buf.asUint8List()).value;
  }

  static LiftRetVal<ConnectOptions?> read(Uint8List buf) {
    if (ByteData.view(buf.buffer, buf.offsetInBytes).getInt8(0) == 0) {
      return LiftRetVal(null, 1);
    }
    final result = FfiConverterConnectOptions.read(
      Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
    );
    return LiftRetVal<ConnectOptions?>(result.value, result.bytesRead + 1);
  }

  static int allocationSize([ConnectOptions? value]) {
    if (value == null) {
      return 1;
    }
    return FfiConverterConnectOptions.allocationSize(value) + 1;
  }

  static RustBuffer lower(ConnectOptions? value) {
    if (value == null) {
      return toRustBuffer(Uint8List.fromList([0]));
    }
    final length = FfiConverterOptionalConnectOptions.allocationSize(value);
    final Pointer<Uint8> frameData = calloc<Uint8>(length);
    final buf = frameData.asTypedList(length);
    FfiConverterOptionalConnectOptions.write(value, buf);
    final bytes = calloc<ForeignBytes>();
    bytes.ref.len = length;
    bytes.ref.data = frameData;
    return RustBuffer.fromBytes(bytes.ref);
  }

  static int write(ConnectOptions? value, Uint8List buf) {
    if (value == null) {
      buf[0] = 0;
      return 1;
    }
    buf[0] = 1;
    return FfiConverterConnectOptions.write(
          value,
          Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
        ) +
        1;
  }
}

class FfiConverterOptionalFetchOptions {
  static FetchOptions? lift(RustBuffer buf) {
    return FfiConverterOptionalFetchOptions.read(buf.asUint8List()).value;
  }

  static LiftRetVal<FetchOptions?> read(Uint8List buf) {
    if (ByteData.view(buf.buffer, buf.offsetInBytes).getInt8(0) == 0) {
      return LiftRetVal(null, 1);
    }
    final result = FfiConverterFetchOptions.read(
      Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
    );
    return LiftRetVal<FetchOptions?>(result.value, result.bytesRead + 1);
  }

  static int allocationSize([FetchOptions? value]) {
    if (value == null) {
      return 1;
    }
    return FfiConverterFetchOptions.allocationSize(value) + 1;
  }

  static RustBuffer lower(FetchOptions? value) {
    if (value == null) {
      return toRustBuffer(Uint8List.fromList([0]));
    }
    final length = FfiConverterOptionalFetchOptions.allocationSize(value);
    final Pointer<Uint8> frameData = calloc<Uint8>(length);
    final buf = frameData.asTypedList(length);
    FfiConverterOptionalFetchOptions.write(value, buf);
    final bytes = calloc<ForeignBytes>();
    bytes.ref.len = length;
    bytes.ref.data = frameData;
    return RustBuffer.fromBytes(bytes.ref);
  }

  static int write(FetchOptions? value, Uint8List buf) {
    if (value == null) {
      buf[0] = 0;
      return 1;
    }
    buf[0] = 1;
    return FfiConverterFetchOptions.write(
          value,
          Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
        ) +
        1;
  }
}

class FfiConverterOptionalSequenceHeader {
  static List<Header>? lift(RustBuffer buf) {
    return FfiConverterOptionalSequenceHeader.read(buf.asUint8List()).value;
  }

  static LiftRetVal<List<Header>?> read(Uint8List buf) {
    if (ByteData.view(buf.buffer, buf.offsetInBytes).getInt8(0) == 0) {
      return LiftRetVal(null, 1);
    }
    final result = FfiConverterSequenceHeader.read(
      Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
    );
    return LiftRetVal<List<Header>?>(result.value, result.bytesRead + 1);
  }

  static int allocationSize([List<Header>? value]) {
    if (value == null) {
      return 1;
    }
    return FfiConverterSequenceHeader.allocationSize(value) + 1;
  }

  static RustBuffer lower(List<Header>? value) {
    if (value == null) {
      return toRustBuffer(Uint8List.fromList([0]));
    }
    final length = FfiConverterOptionalSequenceHeader.allocationSize(value);
    final Pointer<Uint8> frameData = calloc<Uint8>(length);
    final buf = frameData.asTypedList(length);
    FfiConverterOptionalSequenceHeader.write(value, buf);
    final bytes = calloc<ForeignBytes>();
    bytes.ref.len = length;
    bytes.ref.data = frameData;
    return RustBuffer.fromBytes(bytes.ref);
  }

  static int write(List<Header>? value, Uint8List buf) {
    if (value == null) {
      buf[0] = 0;
      return 1;
    }
    buf[0] = 1;
    return FfiConverterSequenceHeader.write(
          value,
          Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
        ) +
        1;
  }
}

class FfiConverterOptionalTrustUpgrades {
  static TrustUpgrades? lift(RustBuffer buf) {
    return FfiConverterOptionalTrustUpgrades.read(buf.asUint8List()).value;
  }

  static LiftRetVal<TrustUpgrades?> read(Uint8List buf) {
    if (ByteData.view(buf.buffer, buf.offsetInBytes).getInt8(0) == 0) {
      return LiftRetVal(null, 1);
    }
    final result = FfiConverterTrustUpgrades.read(
      Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
    );
    return LiftRetVal<TrustUpgrades?>(result.value, result.bytesRead + 1);
  }

  static int allocationSize([TrustUpgrades? value]) {
    if (value == null) {
      return 1;
    }
    return FfiConverterTrustUpgrades.allocationSize(value) + 1;
  }

  static RustBuffer lower(TrustUpgrades? value) {
    if (value == null) {
      return toRustBuffer(Uint8List.fromList([0]));
    }
    final length = FfiConverterOptionalTrustUpgrades.allocationSize(value);
    final Pointer<Uint8> frameData = calloc<Uint8>(length);
    final buf = frameData.asTypedList(length);
    FfiConverterOptionalTrustUpgrades.write(value, buf);
    final bytes = calloc<ForeignBytes>();
    bytes.ref.len = length;
    bytes.ref.data = frameData;
    return RustBuffer.fromBytes(bytes.ref);
  }

  static int write(TrustUpgrades? value, Uint8List buf) {
    if (value == null) {
      buf[0] = 0;
      return 1;
    }
    buf[0] = 1;
    return FfiConverterTrustUpgrades.write(
          value,
          Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
        ) +
        1;
  }
}

class FfiConverterOptionalUint8List {
  static Uint8List? lift(RustBuffer buf) {
    return FfiConverterOptionalUint8List.read(buf.asUint8List()).value;
  }

  static LiftRetVal<Uint8List?> read(Uint8List buf) {
    if (ByteData.view(buf.buffer, buf.offsetInBytes).getInt8(0) == 0) {
      return LiftRetVal(null, 1);
    }
    final result = FfiConverterUint8List.read(
      Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
    );
    return LiftRetVal<Uint8List?>(result.value, result.bytesRead + 1);
  }

  static int allocationSize([Uint8List? value]) {
    if (value == null) {
      return 1;
    }
    return FfiConverterUint8List.allocationSize(value) + 1;
  }

  static RustBuffer lower(Uint8List? value) {
    if (value == null) {
      return toRustBuffer(Uint8List.fromList([0]));
    }
    final length = FfiConverterOptionalUint8List.allocationSize(value);
    final Pointer<Uint8> frameData = calloc<Uint8>(length);
    final buf = frameData.asTypedList(length);
    FfiConverterOptionalUint8List.write(value, buf);
    final bytes = calloc<ForeignBytes>();
    bytes.ref.len = length;
    bytes.ref.data = frameData;
    return RustBuffer.fromBytes(bytes.ref);
  }

  static int write(Uint8List? value, Uint8List buf) {
    if (value == null) {
      buf[0] = 0;
      return 1;
    }
    buf[0] = 1;
    return FfiConverterUint8List.write(
          value,
          Uint8List.view(buf.buffer, buf.offsetInBytes + 1),
        ) +
        1;
  }
}

class FfiConverterSequenceHeader {
  static List<Header> lift(RustBuffer buf) {
    return FfiConverterSequenceHeader.read(buf.asUint8List()).value;
  }

  static LiftRetVal<List<Header>> read(Uint8List buf) {
    List<Header> res = [];
    final length = buf.buffer.asByteData(buf.offsetInBytes).getInt32(0);
    int offset = buf.offsetInBytes + 4;
    for (var i = 0; i < length; i++) {
      final ret = FfiConverterHeader.read(Uint8List.view(buf.buffer, offset));
      offset += ret.bytesRead;
      res.add(ret.value);
    }
    return LiftRetVal(res, offset - buf.offsetInBytes);
  }

  static int write(List<Header> value, Uint8List buf) {
    buf.buffer.asByteData(buf.offsetInBytes).setInt32(0, value.length);
    int offset = buf.offsetInBytes + 4;
    for (var i = 0; i < value.length; i++) {
      offset += FfiConverterHeader.write(
        value[i],
        Uint8List.view(buf.buffer, offset),
      );
    }
    return offset - buf.offsetInBytes;
  }

  static int allocationSize(List<Header> value) {
    return value
            .map((l) => FfiConverterHeader.allocationSize(l))
            .fold(0, (a, b) => a + b) +
        4;
  }

  static RustBuffer lower(List<Header> value) {
    final buf = Uint8List(allocationSize(value));
    write(value, buf);
    return toRustBuffer(buf);
  }
}

class FfiConverterString {
  static String lift(RustBuffer buf) {
    return utf8.decoder.convert(buf.asUint8List());
  }

  static RustBuffer lower(String value) {
    return toRustBuffer(Utf8Encoder().convert(value));
  }

  static LiftRetVal<String> read(Uint8List buf) {
    final end = buf.buffer.asByteData(buf.offsetInBytes).getInt32(0) + 4;
    return LiftRetVal(utf8.decoder.convert(buf, 4, end), end);
  }

  static int allocationSize([String value = ""]) {
    return utf8.encoder.convert(value).length + 4;
  }

  static int write(String value, Uint8List buf) {
    final list = utf8.encoder.convert(value);
    buf.buffer.asByteData(buf.offsetInBytes).setInt32(0, list.length);
    buf.setAll(4, list);
    return list.length + 4;
  }
}

class FfiConverterUInt16 {
  static int lift(int value) => value;
  static LiftRetVal<int> read(Uint8List buf) {
    return LiftRetVal(buf.buffer.asByteData(buf.offsetInBytes).getUint16(0), 2);
  }

  static int lower(int value) {
    if (value < 0 || value > 65535) {
      throw ArgumentError("Value out of range for u16: " + value.toString());
    }
    return value;
  }

  static int allocationSize([int value = 0]) {
    return 2;
  }

  static int write(int value, Uint8List buf) {
    buf.buffer.asByteData(buf.offsetInBytes).setUint16(0, lower(value));
    return 2;
  }
}

class FfiConverterUint8List {
  static Uint8List lift(RustBuffer value) {
    return FfiConverterUint8List.read(value.asUint8List()).value;
  }

  static LiftRetVal<Uint8List> read(Uint8List buf) {
    final length = buf.buffer.asByteData(buf.offsetInBytes).getInt32(0);
    final bytes = Uint8List.view(buf.buffer, buf.offsetInBytes + 4, length);
    return LiftRetVal(bytes, length + 4);
  }

  static RustBuffer lower(Uint8List value) {
    final buf = Uint8List(allocationSize(value));
    write(value, buf);
    return toRustBuffer(buf);
  }

  static int allocationSize([Uint8List? value]) {
    if (value == null) {
      return 4;
    }
    return 4 + value.length;
  }

  static int write(Uint8List value, Uint8List buf) {
    buf.buffer.asByteData(buf.offsetInBytes).setInt32(0, value.length);
    buf.setRange(4, 4 + value.length, value);
    return 4 + value.length;
  }
}

const int UNIFFI_RUST_FUTURE_POLL_READY = 0;
const int UNIFFI_RUST_FUTURE_POLL_MAYBE_READY = 1;
typedef UniffiRustFutureContinuationCallback = Void Function(Uint64, Int8);
final _uniffiRustFutureContinuationHandles = UniffiHandleMap<Completer<int>>();
Future<T> uniffiRustCallAsync<T, F>(
  Pointer<Void> Function() rustFutureFunc,
  void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
  pollFunc,
  F Function(Pointer<Void>, Pointer<RustCallStatus>) completeFunc,
  void Function(Pointer<Void>) freeFunc,
  T Function(F) liftFunc, [
  UniffiRustCallStatusErrorHandler? errorHandler,
]) async {
  final rustFuture = rustFutureFunc();
  final completer = Completer<int>();
  final handle = _uniffiRustFutureContinuationHandles.insert(completer);
  final callbackData = Pointer<Void>.fromAddress(handle);
  late final NativeCallable<UniffiRustFutureContinuationCallback> callback;
  void repoll() {
    pollFunc(rustFuture, callback.nativeFunction, callbackData);
  }

  void onResponse(int data, int pollResult) {
    if (pollResult == UNIFFI_RUST_FUTURE_POLL_READY) {
      final readyCompleter = _uniffiRustFutureContinuationHandles.maybeRemove(
        data,
      );
      if (readyCompleter != null && !readyCompleter.isCompleted) {
        readyCompleter.complete(pollResult);
      }
    } else if (pollResult == UNIFFI_RUST_FUTURE_POLL_MAYBE_READY) {
      repoll();
    } else {
      final errorCompleter = _uniffiRustFutureContinuationHandles.maybeRemove(
        data,
      );
      if (errorCompleter != null && !errorCompleter.isCompleted) {
        errorCompleter.completeError(
          UniffiInternalError.panicked(
            "Unexpected poll result from Rust future: \$pollResult",
          ),
        );
      }
    }
  }

  callback = NativeCallable<UniffiRustFutureContinuationCallback>.listener(
    onResponse,
  );
  try {
    repoll();
    await completer.future;
    final status = calloc<RustCallStatus>();
    try {
      final result = completeFunc(rustFuture, status);
      checkCallStatus(errorHandler ?? NullRustCallStatusErrorHandler(), status);
      return liftFunc(result);
    } finally {
      calloc.free(status);
    }
  } finally {
    callback.close();
    _uniffiRustFutureContinuationHandles.maybeRemove(handle);
    freeFunc(rustFuture);
  }
}

typedef UniffiForeignFutureFree = Void Function(Uint64);
typedef UniffiForeignFutureFreeDart = void Function(int);

class _UniffiForeignFutureState {
  bool cancelled = false;
}

final _uniffiForeignFutureHandleMap =
    UniffiHandleMap<_UniffiForeignFutureState>();
void _uniffiForeignFutureFree(int handle) {
  final state = _uniffiForeignFutureHandleMap.maybeRemove(handle);
  if (state != null) {
    state.cancelled = true;
  }
}

final Pointer<NativeFunction<UniffiForeignFutureFree>>
_uniffiForeignFutureFreePointer = Pointer.fromFunction<UniffiForeignFutureFree>(
  _uniffiForeignFutureFree,
);

final class UniffiForeignFuture extends Struct {
  @Uint64()
  external int handle;
  external Pointer<NativeFunction<UniffiForeignFutureFree>> free;
}

class UniffiHandleMap<T> {
  final Map<int, T> _map = {};
  int _counter = 1;
  int insert(T obj) {
    final handle = _counter;
    _counter += 2;
    _map[handle] = obj;
    return handle;
  }

  T get(int handle) {
    final obj = _map[handle];
    if (obj == null) {
      throw UniffiInternalError(
        UniffiInternalError.unexpectedStaleHandle,
        "Handle not found",
      );
    }
    return obj;
  }

  T remove(int handle) {
    final obj = maybeRemove(handle);
    if (obj == null) {
      throw UniffiInternalError(
        UniffiInternalError.unexpectedStaleHandle,
        "Handle not found",
      );
    }
    return obj;
  }

  T? maybeRemove(int handle) {
    return _map.remove(handle);
  }
}

const _uniffiAssetId = "package:enclavia_dart/uniffi:enclavia_dart_ffi";
@Native<Pointer<Void> Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external Pointer<Void> uniffi_enclavia_ffi_fn_clone_client(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<Void Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external void uniffi_enclavia_ffi_fn_free_client(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<Pointer<Void> Function(RustBuffer, RustBuffer, RustBuffer)>(
  assetId: _uniffiAssetId,
)
external Pointer<Void> uniffi_enclavia_ffi_fn_constructor_client_connect(
  RustBuffer url,
  RustBuffer pcrs,
  RustBuffer options,
);

@Native<
  Pointer<Void> Function(Pointer<Void>, RustBuffer, RustBuffer, RustBuffer)
>(assetId: _uniffiAssetId)
external Pointer<Void> uniffi_enclavia_ffi_fn_method_client_fetch(
  Pointer<Void> ptr,
  RustBuffer method,
  RustBuffer path,
  RustBuffer options,
);

@Native<RustBuffer Function(Uint64, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external RustBuffer ffi_enclavia_ffi_rustbuffer_alloc(
  int size,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<RustBuffer Function(ForeignBytes, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external RustBuffer ffi_enclavia_ffi_rustbuffer_from_bytes(
  ForeignBytes bytes,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<Void Function(RustBuffer, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external void ffi_enclavia_ffi_rustbuffer_free(
  RustBuffer buf,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<RustBuffer Function(RustBuffer, Uint64, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external RustBuffer ffi_enclavia_ffi_rustbuffer_reserve(
  RustBuffer buf,
  int additional,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_u8(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_u8(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_u8(Pointer<Void> handle);

@Native<Uint8 Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external int ffi_enclavia_ffi_rust_future_complete_u8(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_i8(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_i8(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_i8(Pointer<Void> handle);

@Native<Int8 Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external int ffi_enclavia_ffi_rust_future_complete_i8(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_u16(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_u16(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_u16(Pointer<Void> handle);

@Native<Uint16 Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external int ffi_enclavia_ffi_rust_future_complete_u16(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_i16(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_i16(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_i16(Pointer<Void> handle);

@Native<Int16 Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external int ffi_enclavia_ffi_rust_future_complete_i16(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_u32(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_u32(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_u32(Pointer<Void> handle);

@Native<Uint32 Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external int ffi_enclavia_ffi_rust_future_complete_u32(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_i32(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_i32(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_i32(Pointer<Void> handle);

@Native<Int32 Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external int ffi_enclavia_ffi_rust_future_complete_i32(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_u64(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_u64(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_u64(Pointer<Void> handle);

@Native<Uint64 Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external int ffi_enclavia_ffi_rust_future_complete_u64(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_i64(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_i64(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_i64(Pointer<Void> handle);

@Native<Int64 Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external int ffi_enclavia_ffi_rust_future_complete_i64(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_f32(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_f32(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_f32(Pointer<Void> handle);

@Native<Float Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external double ffi_enclavia_ffi_rust_future_complete_f32(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_f64(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_f64(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_f64(Pointer<Void> handle);

@Native<Double Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external double ffi_enclavia_ffi_rust_future_complete_f64(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_rust_buffer(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_rust_buffer(
  Pointer<Void> handle,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_rust_buffer(
  Pointer<Void> handle,
);

@Native<RustBuffer Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external RustBuffer ffi_enclavia_ffi_rust_future_complete_rust_buffer(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<
  Void Function(
    Pointer<Void>,
    Pointer<NativeFunction<UniffiRustFutureContinuationCallback>>,
    Pointer<Void>,
  )
>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_poll_void(
  Pointer<Void> handle,
  Pointer<NativeFunction<UniffiRustFutureContinuationCallback>> callback,
  Pointer<Void> callback_data,
);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_cancel_void(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>)>(assetId: _uniffiAssetId)
external void ffi_enclavia_ffi_rust_future_free_void(Pointer<Void> handle);

@Native<Void Function(Pointer<Void>, Pointer<RustCallStatus>)>(
  assetId: _uniffiAssetId,
)
external void ffi_enclavia_ffi_rust_future_complete_void(
  Pointer<Void> handle,
  Pointer<RustCallStatus> uniffiStatus,
);

@Native<Uint16 Function()>(assetId: _uniffiAssetId)
external int uniffi_enclavia_ffi_checksum_method_client_fetch();

@Native<Uint16 Function()>(assetId: _uniffiAssetId)
external int uniffi_enclavia_ffi_checksum_constructor_client_connect();

@Native<Uint32 Function()>(assetId: _uniffiAssetId)
external int ffi_enclavia_ffi_uniffi_contract_version();

void _checkApiVersion() {
  final bindingsVersion = 30;
  final scaffoldingVersion = ffi_enclavia_ffi_uniffi_contract_version();
  if (bindingsVersion != scaffoldingVersion) {
    throw UniffiInternalError.panicked(
      "UniFFI contract version mismatch: bindings version \$bindingsVersion, scaffolding version \$scaffoldingVersion",
    );
  }
}

void _checkApiChecksums() {
  if (uniffi_enclavia_ffi_checksum_method_client_fetch() != 20199) {
    throw UniffiInternalError.panicked("UniFFI API checksum mismatch");
  }
  if (uniffi_enclavia_ffi_checksum_constructor_client_connect() != 41002) {
    throw UniffiInternalError.panicked("UniFFI API checksum mismatch");
  }
}

void ensureInitialized() {
  _checkApiVersion();
  _checkApiChecksums();
}

@Deprecated("Use ensureInitialized instead")
void initialize() {
  ensureInitialized();
}

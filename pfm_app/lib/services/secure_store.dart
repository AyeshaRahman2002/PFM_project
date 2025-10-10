// lib/services/secure_store.dart
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureStore {
  static const _kBinding = 'device_binding_token';
  static const _storage = FlutterSecureStorage();

  static Future<void> saveBinding(String token) =>
      _storage.write(key: _kBinding, value: token);

  static Future<String?> readBinding() =>
      _storage.read(key: _kBinding);

  static Future<void> clearBinding() =>
      _storage.delete(key: _kBinding);
}

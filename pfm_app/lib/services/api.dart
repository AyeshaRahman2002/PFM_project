// lib/services/api.dart
import 'dart:convert';
import 'dart:io' show Platform;
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

class Api {
  /// Single source of truth for the backend URL.
  /// - Override at build time: --dart-define=API_BASE_URL=https://your.host
  /// - Android emulator needs 10.0.2.2 instead of localhost.
  static String get baseUrl {
    final env = const String.fromEnvironment('API_BASE_URL', defaultValue: '');
    if (env.isNotEmpty) return env;
    return Platform.isAndroid ? 'http://10.0.2.2:8000' : 'http://localhost:8000';
  }

  static const String userAgent = 'PFM/1 (Flutter)';
  static const Duration httpTimeout = Duration(seconds: 12);
}

class ApiClient {
  final http.Client _http;
  ApiClient({http.Client? httpClient}) : _http = httpClient ?? http.Client();

  Future<String?> _token() async {
    final p = await SharedPreferences.getInstance();
    return p.getString('jwt');
  }

  Map<String, String> _authHeaders(String? t) {
    final h = <String, String>{'User-Agent': Api.userAgent};
    if (t != null && t.isNotEmpty) h['Authorization'] = 'Bearer $t';
    return h;
  }

  Future<Map<String, dynamic>> summary(String ym) async {
    final t = await _token();
    if (t == null || t.isEmpty) throw Exception('Not logged in');
    final res = await _http
        .get(Uri.parse('${Api.baseUrl}/insights/summary?month=$ym'), headers: _authHeaders(t))
        .timeout(Api.httpTimeout);
    if (res.statusCode != 200) {
      throw Exception('Summary failed: ${res.statusCode} ${res.body}');
    }
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<List<dynamic>> listTransactions(String ym) async {
    final t = await _token();
    if (t == null || t.isEmpty) throw Exception('Not logged in');
    final res = await _http
        .get(Uri.parse('${Api.baseUrl}/transactions?month=$ym'), headers: _authHeaders(t))
        .timeout(Api.httpTimeout);
    if (res.statusCode != 200) {
      throw Exception('Transactions failed: ${res.statusCode} ${res.body}');
    }
    return jsonDecode(res.body) as List<dynamic>;
  }

  Future<void> createTransaction(Map<String, dynamic> payload) async {
    final t = await _token();
    if (t == null || t.isEmpty) throw Exception('Not logged in');
    final res = await _http
        .post(
          Uri.parse('${Api.baseUrl}/transactions'),
          headers: {
            ..._authHeaders(t),
            'Content-Type': 'application/json',
          },
          body: jsonEncode(payload),
        )
        .timeout(Api.httpTimeout);
    if (res.statusCode != 200 && res.statusCode != 201) {
      throw Exception('Create transaction failed: ${res.statusCode} ${res.body}');
    }
  }
}

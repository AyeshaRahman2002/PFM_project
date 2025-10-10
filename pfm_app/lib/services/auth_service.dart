// lib/services/auth_service.dart
import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:device_info_plus/device_info_plus.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

const baseUrl = 'http://localhost:8000';

Future<Map<String, String>> _collectDeviceInfo() async {
  final di = DeviceInfoPlugin();
  final pi = await PackageInfo.fromPlatform();
  String model = 'unknown', os = 'unknown';

  if (Platform.isAndroid) {
    final a = await di.androidInfo;
    model = '${a.manufacturer} ${a.model}';
    os = 'Android ${a.version.release}';
  } else if (Platform.isIOS) {
    final i = await di.iosInfo;
    model = i.utsname.machine ?? 'iPhone';
    os = 'iOS ${i.systemVersion}';
  } else if (Platform.isMacOS) {
    final m = await di.macOsInfo;
    model = m.model;
    os = 'macOS ${m.osRelease}';
  } else if (Platform.isLinux) {
    final l = await di.linuxInfo;
    model = l.prettyName ?? 'Linux';
    os = 'Linux';
  } else if (Platform.isWindows) {
    final w = await di.windowsInfo;
    model = 'Windows';
    os = 'Windows ${w.majorVersion}.${w.minorVersion}';
  }

  return {
    'model': model,
    'os': os,
    'app_version': pi.version,
    'timezone': DateTime.now().timeZoneName,
    'locale': Platform.localeName,
    'device_id': '$model|$os|${pi.version}|${Platform.localeName}',
  };
}

// lightweight per-device binding storage
const _kBindingKey = 'device_binding_token';

Future<void> _saveBinding(String token) async {
  final p = await SharedPreferences.getInstance();
  await p.setString(_kBindingKey, token);
}

Future<String?> _readBinding() async {
  final p = await SharedPreferences.getInstance();
  return p.getString(_kBindingKey);
}

Future<void> _clearBinding() async {
  final p = await SharedPreferences.getInstance();
  await p.remove(_kBindingKey);
}

Future<String> _userAgent() async {
  final pi = await PackageInfo.fromPlatform();
  return 'PFM/${pi.version} (Flutter; dart:http)';
}

class AuthService {
  // Auth
  Future<Map<String, dynamic>> login(String email, String password) async {
    final device = await _collectDeviceInfo();
    final binding = await _readBinding();
    final ua = await _userAgent();

    final res = await http.post(
      Uri.parse('$baseUrl/auth/login'),
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': ua,
        if (binding != null && binding.isNotEmpty) 'x-device-binding': binding,
      },
      body: jsonEncode({
        'email': email,
        'password': password,
        'device': device,
        if (binding != null && binding.isNotEmpty) 'device_binding': binding,
      }),
    );

    if (res.statusCode == 423) {
      throw Exception('Account locked temporarily (too many failed attempts). Try later.');
    }
    if (res.statusCode == 403) {
      throw Exception('Login blocked for security (hard deny).');
    }
    if (res.statusCode != 200) {
      throw Exception('Login failed: ${res.body}');
    }
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<void> register(String email, String password) async {
    final res = await http.post(
      Uri.parse('$baseUrl/auth/register'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': email, 'password': password}),
    );
    if (res.statusCode != 200) {
      throw Exception('Register failed: ${res.body}');
    }
  }

  // Profile
  Future<Map<String, dynamic>> getProfile(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/profile'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) {
      throw Exception('Get profile failed: ${res.body}');
    }
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> updateProfile(
    String token,
    Map<String, dynamic> data,
  ) async {
    final res = await http.put(
      Uri.parse('$baseUrl/profile'),
      headers: {
        'Authorization': 'Bearer $token',
        'Content-Type': 'application/json',
      },
      body: jsonEncode(data),
    );
    if (res.statusCode != 200) {
      throw Exception('Update profile failed: ${res.body}');
    }
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> uploadAvatar(String token, File file) async {
    final req = http.MultipartRequest('POST', Uri.parse('$baseUrl/profile/avatar'));
    req.headers['Authorization'] = 'Bearer $token';
    req.files.add(await http.MultipartFile.fromPath('file', file.path));
    final streamed = await req.send();
    final res = await http.Response.fromStream(streamed);
    if (res.statusCode != 200) {
      throw Exception('Upload avatar failed: ${res.body}');
    }
    final Map<String, dynamic> parsed = jsonDecode(res.body) as Map<String, dynamic>;
    if (parsed.containsKey('avatar_url')) return {'avatar_url': parsed['avatar_url']};
    return parsed;
  }

  // Security Center
  Future<List<dynamic>> listDevices(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/security/devices'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Devices failed: ${res.body}');
    return jsonDecode(res.body) as List<dynamic>;
  }

  Future<void> trustDevice(String token, String deviceHash) async {
    final res = await http.post(
      Uri.parse('$baseUrl/security/devices/$deviceHash/trust'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Trust failed: ${res.body}');
  }

  // Bind/unbind device to establish a device-binding token
  Future<Map<String, dynamic>> bindDevice(String token, String deviceHash) async {
    final res = await http.post(
      Uri.parse('$baseUrl/security/devices/$deviceHash/bind'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Bind failed: ${res.body}');
    final out = jsonDecode(res.body) as Map<String, dynamic>;
    final raw = out['device_binding'] as String?;
    if (raw != null && raw.isNotEmpty) {
      await _saveBinding(raw);
    }
    return out;
  }

  Future<void> unbindDevice(String token, String deviceHash) async {
    final res = await http.post(
      Uri.parse('$baseUrl/security/devices/$deviceHash/unbind'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Unbind failed: ${res.body}');
    await _clearBinding();
  }

  Future<List<dynamic>> listLogins(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/security/logins'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Logins failed: ${res.body}');
    return jsonDecode(res.body) as List<dynamic>;
  }

  Future<List<dynamic>> listSessions(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/security/sessions'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Sessions failed: ${res.body}');
    return jsonDecode(res.body) as List<dynamic>;
  }

  Future<Map<String, dynamic>> impossibleTravel(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/security/impossible_travel'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Impossible travel failed: ${res.body}');
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> anomalyScore(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/transactions/anomaly_score'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Anomaly score failed: ${res.body}');
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> rulesTest(String token, Map<String, dynamic> payload) async {
    final res = await http.post(
      Uri.parse('$baseUrl/rules/test'),
      headers: {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'},
      body: jsonEncode(payload),
    );
    if (res.statusCode != 200) throw Exception('Rules test failed: ${res.body}');
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<String> exportAuditNdjson(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/export/audit'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Export failed: ${res.body}');
    return res.body; // NDJSON string
  }

  /// security analytics (30-day daily counts & device totals)
  Future<Map<String, dynamic>> securityMetrics(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/security/metrics'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Metrics failed: ${res.body}');
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  /// recent successful login geos (for map/list)
  Future<Map<String, dynamic>> geoLogins(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/security/geo_logins'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Geo logins failed: ${res.body}');
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  // Intelligence
  Future<Map<String, dynamic>> intelProfile(String token) async {
    final res = await http.get(
      Uri.parse('$baseUrl/intelligence/profile'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 200) throw Exception('Intel profile failed: ${res.body}');
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> intelScoreTx(
    String token, {
    required double amount,
    String currency = 'SAR',
    required String category,
    String? merchant,
  }) async {
    final res = await http.post(
      Uri.parse('$baseUrl/intelligence/score/tx'),
      headers: {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'},
      body: jsonEncode({
        'amount': amount,
        'currency': currency,
        'category': category,
        'merchant': merchant,
      }),
    );
    if (res.statusCode != 200) throw Exception('Score TX failed: ${res.body}');
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> intelScoreLogin(
    String token, {
    String? ip,
    String? deviceHash,
    String? userAgent,
  }) async {
    final res = await http.post(
      Uri.parse('$baseUrl/intelligence/score/login'),
      headers: {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'},
      body: jsonEncode({
        'ip': ip,
        'device_hash': deviceHash,
        'user_agent': userAgent,
      }),
    );
    if (res.statusCode != 200) throw Exception('Score login failed: ${res.body}');
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  // Risk Config (optional admin)
  Future<Map<String, dynamic>> getRiskConfig(String token) async {
    final r = await http.get(Uri.parse('$baseUrl/risk/config'),
        headers: {'Authorization': 'Bearer $token'});
    if (r.statusCode != 200) throw Exception('Get config failed: ${r.body}');
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> putRiskConfig(String token, Map<String, dynamic> body) async {
    final r = await http.put(Uri.parse('$baseUrl/risk/config'),
        headers: {'Authorization': 'Bearer $token','Content-Type':'application/json'},
        body: jsonEncode(body));
    if (r.statusCode != 200) throw Exception('Update config failed: ${r.body}');
    return jsonDecode(r.body) as Map<String, dynamic>;
  }

  // Account Deletion
  Future<void> deleteAccount(String token) async {
    final res = await http.delete(
      Uri.parse('$baseUrl/me'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode != 204) throw Exception('Delete account failed: ${res.body}');
  }
}

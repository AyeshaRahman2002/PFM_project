// lib/state/auth_state.dart
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AuthState extends ChangeNotifier {
  String? _token;
  String? _email;

  String? get token => _token;
  String? get email => _email;
  bool get isAuthenticated => _token != null && _token!.isNotEmpty;

  Future<void> loadFromStorage() async {
    final prefs = await SharedPreferences.getInstance();
    _token = prefs.getString('jwt');
    _email = prefs.getString('email');
    notifyListeners();
  }

  Future<void> setSession({required String token, required String email}) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('jwt', token);
    await prefs.setString('email', email);
    _token = token;
    _email = email;
    notifyListeners();
  }

  Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('jwt');
    await prefs.remove('email');
    _token = null;
    _email = null;
    notifyListeners();
  }
}

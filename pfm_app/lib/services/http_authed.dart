// lib/services/http_authed.dart
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:flutter/widgets.dart';
import 'package:provider/provider.dart';
import '../state/auth_state.dart';
import 'api.dart';

Future<http.Response> authedPost(
  BuildContext context,
  String path,
  Map<String, dynamic> body,
) async {
  final auth = context.read<AuthState>();
  if (!auth.isAuthenticated) throw Exception('Not logged in');
  return http
      .post(
        Uri.parse('${Api.baseUrl}$path'),
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ${auth.token}',
          'User-Agent': Api.userAgent,
        },
        body: jsonEncode(body),
      )
      .timeout(Api.httpTimeout);
}

Future<http.Response> authedGet(BuildContext context, String path) async {
  final auth = context.read<AuthState>();
  if (!auth.isAuthenticated) throw Exception('Not logged in');
  return http
      .get(
        Uri.parse('${Api.baseUrl}$path'),
        headers: {
          'Authorization': 'Bearer ${auth.token}',
          'User-Agent': Api.userAgent,
        },
      )
      .timeout(Api.httpTimeout);
}

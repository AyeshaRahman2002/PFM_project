// lib/screens/settings_screen.dart
import 'dart:io';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../services/auth_service.dart';
import '../services/api.dart';
import '../state/auth_state.dart';
import 'security_center.dart';
import 'step_up_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});
  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final _emailCtrl = TextEditingController(text: 'you@example.com');
  final _passCtrl = TextEditingController();
  final _authApi = AuthService();
  bool _busy = false;

  Future<void> _register() async {
    setState(() => _busy = true);
    try {
      await _authApi.register(_emailCtrl.text.trim(), _passCtrl.text);
      await _login(showSnack: false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Registered & logged in')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Register failed: $e')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _login({bool showSnack = true}) async {
    setState(() => _busy = true);
    try {
      final data = await _authApi.login(_emailCtrl.text.trim(), _passCtrl.text);

      final token = data['access_token'] ?? data['token'];
      final risk = (data['risk_score'] ?? 0) as int;
      final stepUp = (data['step_up_required'] ?? false) as bool;

      if (mounted) {
        final msg = stepUp
            ? 'Suspicious login • risk $risk. Consider enabling TOTP/WebAuthn.'
            : 'Logged in • risk $risk.';
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
      }

      if (mounted && stepUp) {
        // Send user to a simple OTP step-up screen
        await Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => const StepUpScreen()),
        );
      }

      if (token == null) throw Exception('No token in response');
      await context.read<AuthState>().setSession(
            token: token,
            email: _emailCtrl.text.trim(),
          );
      if (mounted && showSnack) {
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('Logged in')));
      }
    } catch (e) {
      if (!mounted) return;
      final msg = () {
        final s = e.toString();
        if (s.contains('locked temporarily')) {
          return 'Account locked temporarily. Try again later.';
        }
        if (s.contains('blocked for security')) {
          return 'Login blocked by risk rules. Use a trusted device or try later.';
        }
        return 'Login failed: $e';
      }();
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthState>();
    if (auth.isAuthenticated) {
      return _ProfilePane(email: auth.email!);
    }
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          TextField(
            controller: _emailCtrl,
            decoration: const InputDecoration(labelText: 'Email'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _passCtrl,
            decoration: const InputDecoration(labelText: 'Password'),
            obscureText: true,
          ),
          const SizedBox(height: 20),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              OutlinedButton(
                onPressed: _busy ? null : _register,
                child: _busy
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Register'),
              ),
              const SizedBox(width: 12),
              FilledButton(
                onPressed: _busy ? null : _login,
                child: _busy
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Text('Login'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _ProfilePane extends StatefulWidget {
  const _ProfilePane({required this.email});
  final String email;
  @override
  State<_ProfilePane> createState() => _ProfilePaneState();
}

class _ProfilePaneState extends State<_ProfilePane> {
  final _svc = AuthService();
  bool _loading = true;
  bool _saving = false;

  final _firstCtrl = TextEditingController();
  final _lastCtrl = TextEditingController();
  DateTime? _dob;
  final _nationCtrl = TextEditingController();

  String? _avatarUrl; // server path or absolute URL
  String? _avatarBust; // preview URL with cache-buster

  @override
  void initState() {
    super.initState();
    _loadProfile();
  }

  Future<void> _loadProfile() async {
    setState(() => _loading = true);
    try {
      final token = context.read<AuthState>().token!;
      final p = await _svc.getProfile(token);
      _firstCtrl.text = (p['first_name'] ?? '') as String;
      _lastCtrl.text = (p['last_name'] ?? '') as String;
      _nationCtrl.text = (p['nationality'] ?? '') as String;
      final dobStr = p['dob'] as String?;
      _dob = dobStr != null ? DateTime.tryParse(dobStr) : null;
      _avatarUrl = p['avatar_url'] as String?;
      _refreshAvatarBust();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Profile load failed: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _saveProfile() async {
    setState(() => _saving = true);
    try {
      final token = context.read<AuthState>().token!;
      final body = {
        'first_name': _firstCtrl.text.trim(),
        'last_name': _lastCtrl.text.trim(),
        'nationality': _nationCtrl.text.trim(),
        'dob': _dob == null ? null : _dob!.toIso8601String().split('T').first,
      };
      final updated = await _svc.updateProfile(token, body);
      _avatarUrl = updated['avatar_url'] as String?;
      _refreshAvatarBust();
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('Profile saved')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Save failed: $e')));
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _pickAndUploadAvatar() async {
    try {
      final res = await FilePicker.platform.pickFiles(type: FileType.image);
      if (res == null || res.files.single.path == null) return;
      final file = File(res.files.single.path!);
      final token = context.read<AuthState>().token!;
      final uploaded = await _svc.uploadAvatar(token, file);
      _avatarUrl = uploaded['avatar_url'] as String?;
      _refreshAvatarBust();
      setState(() {});
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Avatar upload failed: $e')));
    }
  }

  Future<void> _confirmAndDeleteAccount() async {
    final yes = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete account?'),
        content: const Text(
          'This will permanently delete your account and all data (transactions, budgets, goals). This action cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (yes != true) return;

    try {
      final token = context.read<AuthState>().token!;
      await _svc.deleteAccount(token);
      await context.read<AuthState>().clear();
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(const SnackBar(content: Text('Account deleted')));
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Delete failed: $e')));
    }
  }

  // helpers for avatar preview/cache-busting
  String? get _avatarPreviewUrl {
    if (_avatarUrl == null || _avatarUrl!.isEmpty) return null;
    if (_avatarUrl!.startsWith('/')) return '${Api.baseUrl}${_avatarUrl!}';
    if (_avatarUrl!.startsWith('http://') ||
        _avatarUrl!.startsWith('https://')) {
      return _avatarUrl!;
    }
    return _avatarUrl!;
  }

  void _refreshAvatarBust() {
    final base = _avatarPreviewUrl;
    _avatarBust =
        base == null ? null : '$base?v=${DateTime.now().millisecondsSinceEpoch}';
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    return Padding(
      padding: const EdgeInsets.all(16),
      child: ListView(
        children: [
          Row(
            children: [
              CircleAvatar(
                radius: 36,
                backgroundImage:
                    _avatarBust == null ? null : NetworkImage(_avatarBust!),
                child: _avatarBust == null
                    ? const Icon(Icons.person, size: 36)
                    : null,
              ),
              const SizedBox(width: 12),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(widget.email,
                      style: Theme.of(context).textTheme.titleMedium),
                  Text('Profile',
                      style: Theme.of(context).textTheme.bodySmall),
                ],
              ),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.photo_camera),
                onPressed: _pickAndUploadAvatar,
                tooltip: 'Change avatar',
              ),
            ],
          ),
          const SizedBox(height: 20),

          TextField(
            controller: _firstCtrl,
            decoration: const InputDecoration(labelText: 'First name'),
          ),
          const SizedBox(height: 12),

          TextField(
            controller: _lastCtrl,
            decoration: const InputDecoration(labelText: 'Last name'),
          ),
          const SizedBox(height: 12),

          ListTile(
            contentPadding: EdgeInsets.zero,
            title: Text(
              'Date of birth: ${_dob == null ? '—' : _dob!.toIso8601String().split('T').first}',
            ),
            trailing: IconButton(
              icon: const Icon(Icons.calendar_today_outlined),
              onPressed: () async {
                final picked = await showDatePicker(
                  context: context,
                  firstDate: DateTime(1900),
                  lastDate: DateTime.now(),
                  initialDate: _dob ?? DateTime(2000, 1, 1),
                );
                if (picked != null) setState(() => _dob = picked);
              },
            ),
          ),

          TextField(
            controller: _nationCtrl,
            decoration: const InputDecoration(labelText: 'Nationality'),
          ),

          const SizedBox(height: 16),
          Row(
            children: [
              FilledButton(
                onPressed: _saving ? null : _saveProfile,
                child: _saving
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Save changes'),
              ),
              const SizedBox(width: 12),
              FilledButton.tonal(
                onPressed: () async {
                  await context.read<AuthState>().clear();
                  if (!mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Logged out')),
                  );
                },
                child: const Text('Logout'),
              ),
            ],
          ),

          const SizedBox(height: 20),

          // Security Center entry
          ListTile(
            leading: const Icon(Icons.security),
            title: const Text('Security Center'),
            subtitle: const Text('Devices, logins, and alerts'),
            onTap: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) => const SecurityCenterScreen(),
              ),
            ),
          ),

          const SizedBox(height: 24),
          const Divider(),
          const SizedBox(height: 12),

          // Delete account
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            onPressed: _confirmAndDeleteAccount,
            child: const Text('Delete account'),
          ),
        ],
      ),
    );
  }
}

// lib/screens/step_up_screen.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/auth_service.dart';
import '../state/auth_state.dart';

class StepUpScreen extends StatefulWidget {
  const StepUpScreen({super.key});
  @override
  State<StepUpScreen> createState() => _StepUpScreenState();
}

class _StepUpScreenState extends State<StepUpScreen> {
  final _svc = AuthService();
  bool _starting = true;
  String? _nonceToken; // some servers return a token to bind verification
  String? _serverHint; // may include test_code in dev
  final _codeCtrl = TextEditingController();
  bool _verifying = false;

  @override
  void initState() {
    super.initState();
    _start();
  }

  Future<void> _start() async {
    setState(() => _starting = true);
    try {
      final token = context.read<AuthState>().token; // may be null pre-login
      final resp = await _svc.stepUpStart(token: token);
      _nonceToken = (resp['token'] as String?);
      final code = resp['code'] ?? resp['test_code'];
      if (code != null) {
        _serverHint = 'Dev code: $code';
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Start failed: $e')),
      );
    } finally {
      if (mounted) setState(() => _starting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Step-up verification')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: _starting
            ? const Center(child: CircularProgressIndicator())
            : Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Enter the one-time code sent to you (demo uses test code).'),
                  if (_serverHint != null) ...[
                    const SizedBox(height: 8),
                    Text(_serverHint!, style: const TextStyle(color: Colors.black54)),
                  ],
                  const SizedBox(height: 12),
                  TextField(
                    controller: _codeCtrl,
                    decoration: const InputDecoration(labelText: 'OTP code'),
                    keyboardType: TextInputType.number,
                  ),
                  const SizedBox(height: 12),
                  FilledButton(
                    onPressed: _verifying
                        ? null
                        : () async {
                            setState(() => _verifying = true);
                            try {
                              final ok = await _svc.stepUpVerify(
                                token: context.read<AuthState>().token,
                                code: _codeCtrl.text.trim(),
                                nonceToken: _nonceToken,
                              );
                              if (!mounted) return;
                              if (ok) {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  const SnackBar(content: Text('Step-up verified')),
                                );
                                Navigator.pop(context, true);
                              } else {
                                ScaffoldMessenger.of(context).showSnackBar(
                                  const SnackBar(content: Text('Verification failed')),
                                );
                              }
                            } catch (e) {
                              if (!mounted) return;
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text('Verify failed: $e')),
                              );
                            } finally {
                              if (mounted) setState(() => _verifying = false);
                            }
                          },
                    child: _verifying
                        ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                        : const Text('Verify'),
                  ),
                ],
              ),
      ),
    );
  }
}

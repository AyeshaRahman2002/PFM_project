// lib/screens/step_up_screen.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/auth_service.dart';
import '../state/auth_state.dart';

class StepUpScreen extends StatefulWidget {
  final String challengeId; // from /auth/login -> pending_challenge
  const StepUpScreen({super.key, required this.challengeId});

  @override
  State<StepUpScreen> createState() => _StepUpScreenState();
}

class _StepUpScreenState extends State<StepUpScreen> {
  final _svc = AuthService();
  final _codeCtrl = TextEditingController();
  bool _verifying = false;

  @override
  void dispose() {
    _codeCtrl.dispose();
    super.dispose();
  }

  Future<void> _verify() async {
    setState(() => _verifying = true);
    try {
      final auth = context.read<AuthState>();
      final bearer = auth.token;
      if (bearer == null || bearer.isEmpty) {
        throw Exception('Missing bearer token from initial login');
      }

      // Verify the TOTP and get a *new* final JWT
      final resp = await _svc.stepUpVerify(
        bearerToken: bearer,
        challengeId: widget.challengeId,
        code: _codeCtrl.text.trim(),
      );

      final newToken = (resp['access_token'] as String?) ?? '';
      if (newToken.isEmpty) {
        throw Exception('No access_token in verify response');
      }

      // Replace the provisional token with the fully-verified token
      await auth.setSession(token: newToken, email: auth.email ?? '');

      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Step-up verified')),
      );
      Navigator.pop(context, true);
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Verification failed: $e')),
      );
    } finally {
      if (mounted) setState(() => _verifying = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final hintStyle =
        Theme.of(context).textTheme.bodySmall?.copyWith(color: Colors.black54);
    return Scaffold(
      appBar: AppBar(title: const Text('Step-up verification')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Enter the 6-digit code from your authenticator app.'),
            const SizedBox(height: 8),
            Text('Challenge: ${widget.challengeId}', style: hintStyle),
            const SizedBox(height: 12),
            TextField(
              controller: _codeCtrl,
              decoration: const InputDecoration(
                labelText: 'TOTP code',
                hintText: '123456',
              ),
              keyboardType: TextInputType.number,
              autofillHints: const [AutofillHints.oneTimeCode],
            ),
            const SizedBox(height: 12),
            FilledButton(
              onPressed: _verifying ? null : _verify,
              child: _verifying
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Text('Verify'),
            ),
          ],
        ),
      ),
    );
  }
}

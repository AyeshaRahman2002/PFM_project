// screens/add_expense_screen.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:intl/intl.dart';

import '../state/auth_state.dart';
import '../services/http_authed.dart';
import '../ui/widgets.dart';

class AddExpenseScreen extends StatefulWidget {
  const AddExpenseScreen({super.key});
  @override
  State<AddExpenseScreen> createState() => _AddExpenseScreenState();
}

class _AddExpenseScreenState extends State<AddExpenseScreen> {
  final _amountCtrl = TextEditingController();
  String _category = 'Food';
  DateTime _date = DateTime.now();
  final _merchantCtrl = TextEditingController();
  final _notesCtrl = TextEditingController();
  bool _busy = false;

  Future<void> _save() async {
    setState(() => _busy = true);
    try {
      final dateStr = DateFormat('yyyy-MM-dd').format(_date);
      final res = await authedPost(context, '/transactions', {
        'amount': double.tryParse(_amountCtrl.text) ?? 0,
        'category': _category,
        'date': dateStr,
        'merchant': _merchantCtrl.text.isEmpty ? null : _merchantCtrl.text,
        'notes': _notesCtrl.text.isEmpty ? null : _notesCtrl.text,
      });
      if (res.statusCode == 200 || res.statusCode == 201) {
        if (mounted) {
          ScaffoldMessenger.of(context)
              .showSnackBar(const SnackBar(content: Text('Expense added')));
        }
        _amountCtrl.clear();
        _merchantCtrl.clear();
        _notesCtrl.clear();
        setState(() {
          _category = 'Food';
          _date = DateTime.now();
        });
      } else if (res.statusCode == 401) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Please login again')));
        }
      } else {
        throw Exception(res.body);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Error: $e')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthState>();

    if (!auth.isAuthenticated) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Please login to add expenses'),
            const SizedBox(height: 12),
            FilledButton(
              onPressed: () {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Open Settings → Login')),
                );
              },
              child: const Text('Go to Settings'),
            ),
          ],
        ),
      );
    }

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 24),
        child: ListView(
          children: [
            SectionCard(
              title: 'New expense',
              children: [
                AmountField(controller: _amountCtrl),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    for (final v in ['25', '50', '100', '250'])
                      ActionChip(
                        label: Text('+$v'),
                        onPressed: () {
                          final cur = double.tryParse(_amountCtrl.text) ?? 0;
                          final add = double.parse(v);
                          _amountCtrl.text =
                              (cur + add).toStringAsFixed(2);
                        },
                      ),
                  ],
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    for (final c in const [
                      'Food',
                      'Shopping',
                      'Transport',
                      'Bills',
                      'Entertainment',
                      'Other'
                    ])
                      ChoiceChip(
                        label: Text(c),
                        selected: _category == c,
                        onSelected: (_) => setState(() => _category = c),
                      ),
                  ],
                ),
                const SizedBox(height: 12),
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(
                      'Date: ${_date.toIso8601String().split('T').first}'),
                  trailing: IconButton(
                    icon: const Icon(Icons.calendar_today_outlined),
                    onPressed: () async {
                      final picked = await showDatePicker(
                        context: context,
                        firstDate: DateTime(2020),
                        lastDate: DateTime(2100),
                        initialDate: _date,
                      );
                      if (picked != null) setState(() => _date = picked);
                    },
                  ),
                ),
                TextField(
                  controller: _merchantCtrl,
                  decoration: const InputDecoration(
                      labelText: 'Merchant (optional)'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: _notesCtrl,
                  decoration:
                      const InputDecoration(labelText: 'Notes (optional)'),
                ),
                const SizedBox(height: 16),
                Row(
                  children: [
                    Expanded(
                      child: FilledButton(
                        onPressed: _busy ? null : _save,
                        child: _busy
                            ? const SizedBox(
                                width: 16,
                                height: 16,
                                child: CircularProgressIndicator(
                                    strokeWidth: 2),
                              )
                            : const Text('Save'),
                      ),
                    ),
                    const SizedBox(width: 8),
                    IconButton.filledTonal(
                      tooltip: 'Reset',
                      onPressed: () {
                        _amountCtrl.clear();
                        _merchantCtrl.clear();
                        _notesCtrl.clear();
                        setState(() {
                          _category = 'Food';
                          _date = DateTime.now();
                        });
                      },
                      icon: const Icon(Icons.refresh),
                    )
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

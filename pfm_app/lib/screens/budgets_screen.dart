// lib/screens/budgets_screen.dart
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../services/http_authed.dart';
import '../ui/widgets.dart';
import '../utils/format.dart';

class BudgetsScreen extends StatefulWidget {
  const BudgetsScreen({super.key});
  @override
  State<BudgetsScreen> createState() => _BudgetsScreenState();
}

class _BudgetsScreenState extends State<BudgetsScreen> {
  final _limitCtrl = TextEditingController();
  String _category = 'Food';
  late final String _ym;
  List<dynamic> _budgets = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _ym = DateFormat('yyyy-MM').format(DateTime.now());
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final res = await authedGet(context, '/budgets?month=$_ym');
      if (res.statusCode != 200) throw Exception(res.body);
      setState(() => _budgets = jsonDecode(res.body) as List<dynamic>);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Failed to load: $e')));
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _save() async {
    final now = DateTime.now();
    final payload = {
      'category': _category,
      'amount': double.tryParse(_limitCtrl.text) ?? 0,
      'month': now.month,
      'year': now.year,
    };
    try {
      final res = await authedPost(context, '/budgets', payload);
      if (res.statusCode != 200 && res.statusCode != 201) {
        throw Exception(res.body);
      }
      _limitCtrl.clear();
      await _load();
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('Budget saved')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Save failed: $e')));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Budgets')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  SectionCard(
                    title: 'Set monthly budget ($_ym)',
                    children: [
                      Row(
                        children: [
                          DropdownButton<String>(
                            value: _category,
                            items: const [
                              DropdownMenuItem(
                                  value: 'Food', child: Text('Food')),
                              DropdownMenuItem(
                                  value: 'Shopping', child: Text('Shopping')),
                              DropdownMenuItem(
                                  value: 'Transport', child: Text('Transport')),
                              DropdownMenuItem(
                                  value: 'Bills', child: Text('Bills')),
                              DropdownMenuItem(
                                  value: 'Entertainment',
                                  child: Text('Entertainment')),
                            ],
                            onChanged: (v) =>
                                setState(() => _category = v ?? 'Food'),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: AmountField(
                                controller: _limitCtrl, label: 'Limit (SAR)'),
                          ),
                          const SizedBox(width: 8),
                          FilledButton(
                              onPressed: _save, child: const Text('Save')),
                        ],
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text('Your budgets',
                      style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 6),
                  for (final b in _budgets)
                    Card(
                      child: ListTile(
                        title: Text(b['category'].toString()),
                        subtitle: Text('Month ${b['month']}/${b['year']}'),
                        trailing:
                            Text(sar((b['amount'] as num).toDouble())),
                      ),
                    ),
                ],
              ),
            ),
    );
  }
}

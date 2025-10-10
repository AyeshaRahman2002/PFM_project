// lib/screens/goals_screen.dart
import 'dart:convert';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../services/http_authed.dart';
import '../ui/widgets.dart';
import '../utils/format.dart';

class GoalsScreen extends StatefulWidget {
  const GoalsScreen({super.key});
  @override
  State<GoalsScreen> createState() => _GoalsScreenState();
}

class _GoalsScreenState extends State<GoalsScreen> {
  final _nameCtrl = TextEditingController();
  final _targetCtrl = TextEditingController();
  DateTime _targetDate = DateTime.now().add(const Duration(days: 90));

  List<dynamic> _goals = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final res = await authedGet(context, '/goals');
      if (res.statusCode != 200) throw Exception(res.body);
      setState(() => _goals = jsonDecode(res.body) as List<dynamic>);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Failed to load: $e')));
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _createGoal() async {
    final payload = {
      'name': _nameCtrl.text.trim(),
      'target_amount': double.tryParse(_targetCtrl.text) ?? 0,
      'target_date': DateFormat('yyyy-MM-dd').format(_targetDate),
    };
    try {
      final res = await authedPost(context, '/goals', payload);
      if (res.statusCode != 200 && res.statusCode != 201) {
        throw Exception(res.body);
      }
      _nameCtrl.clear();
      _targetCtrl.clear();
      await _load();
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('Goal created')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Create failed: $e')));
      }
    }
  }

  Future<void> _contribute(int goalId) async {
    final amount = await _askAmount();
    if (amount == null) return;
    try {
      final res =
          await authedPost(context, '/goals/$goalId/contribute', {'amount': amount});
      if (res.statusCode != 200 && res.statusCode != 201) {
        throw Exception(res.body);
      }
      await _load();
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('Contribution added')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Contribution failed: $e')));
      }
    }
  }

  Future<double?> _askAmount() async {
    final ctrl = TextEditingController();
    return showDialog<double>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Add contribution'),
        content: TextField(
          controller: ctrl,
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
          decoration: const InputDecoration(labelText: 'Amount (SAR)'),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel')),
          FilledButton(
            onPressed: () {
              final v = double.tryParse(ctrl.text);
              Navigator.pop(ctx, v);
            },
            child: const Text('Add'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Goals')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  SectionCard(
                    title: 'Create a goal',
                    children: [
                      TextField(
                        controller: _nameCtrl,
                        decoration: const InputDecoration(labelText: 'Name'),
                      ),
                      const SizedBox(height: 8),
                      TextField(
                        controller: _targetCtrl,
                        decoration: const InputDecoration(
                            labelText: 'Target amount (SAR)'),
                        keyboardType:
                            const TextInputType.numberWithOptions(decimal: true),
                      ),
                      const SizedBox(height: 8),
                      ListTile(
                        contentPadding: EdgeInsets.zero,
                        title: Text(
                            'Target date: ${DateFormat('yyyy-MM-dd').format(_targetDate)}'),
                        trailing: IconButton(
                          icon: const Icon(Icons.calendar_today_outlined),
                          onPressed: () async {
                            final picked = await showDatePicker(
                              context: context,
                              firstDate: DateTime.now(),
                              lastDate: DateTime(2100),
                              initialDate: _targetDate,
                            );
                            if (picked != null) {
                              setState(() => _targetDate = picked);
                            }
                          },
                        ),
                      ),
                      Align(
                        alignment: Alignment.centerRight,
                        child: FilledButton(
                          onPressed: _createGoal,
                          child: const Text('Create'),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text('Your goals',
                      style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 6),
                  for (final g in _goals)
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 10),
                        child: Row(
                          children: [
                            _RadialProgress(
                              value: ((g['current_amount'] ?? 0) as num)
                                      .toDouble() /
                                  ((g['target_amount'] ?? 1) as num)
                                      .toDouble(),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(g['name'],
                                      style: Theme.of(context)
                                          .textTheme
                                          .titleMedium),
                                  const SizedBox(height: 4),
                                  Text(
                                      '${sar(g['current_amount'] ?? 0)} / ${sar(g['target_amount'] ?? 0)} • target ${g['target_date']}'),
                                  const SizedBox(height: 6),
                                  Row(
                                    children: [
                                      Expanded(
                                        child: FilledButton.tonal(
                                          onPressed: () =>
                                              _contribute(g['id'] as int),
                                          child: const Text('Contribute'),
                                        ),
                                      ),
                                    ],
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                ],
              ),
            ),
    );
  }
}

class _RadialProgress extends StatelessWidget {
  final double value; // 0..1
  const _RadialProgress({required this.value});
  @override
  Widget build(BuildContext context) {
    final v = value.clamp(0.0, 1.0);
    return SizedBox(
      width: 46,
      height: 46,
      child: CustomPaint(
        painter: _ArcPainter(v, Theme.of(context).colorScheme.primary),
        child: Center(
          child: Text('${(v * 100).round()}%',
              style: const TextStyle(fontSize: 10)),
        ),
      ),
    );
  }
}

class _ArcPainter extends CustomPainter {
  final double v;
  final Color c;
  _ArcPainter(this.v, this.c);
  @override
  void paint(Canvas canvas, Size size) {
    final r = math.min(size.width, size.height) / 2;
    final center = Offset(size.width / 2, size.height / 2);
    final bg = Paint()
      ..color = c.withOpacity(.15)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 6
      ..strokeCap = StrokeCap.round;
    final fg = Paint()
      ..color = c
      ..style = PaintingStyle.stroke
      ..strokeWidth = 6
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(Rect.fromCircle(center: center, radius: r), -math.pi / 2,
        2 * math.pi, false, bg);
    canvas.drawArc(Rect.fromCircle(center: center, radius: r), -math.pi / 2,
        2 * math.pi * v, false, fg);
  }

  @override
  bool shouldRepaint(covariant _ArcPainter old) => old.v != v || old.c != c;
}

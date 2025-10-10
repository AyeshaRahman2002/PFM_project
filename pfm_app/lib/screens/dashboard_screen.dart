// lib/screens/dashboard_screen.dart
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:fl_chart/fl_chart.dart';

import '../services/api.dart';
import '../services/http_authed.dart';
import '../models/tx.dart';
import '../ui/widgets.dart';
import '../utils/format.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  final api = ApiClient();

  DateTime _month = DateTime.now();

  Map<String, dynamic>? summary;
  List<Tx> txs = [];
  List<_BudgetRow> budgetRows = [];

  bool _loading = true;

  String get _ym => DateFormat('yyyy-MM').format(_month);
  String get _monthLabel => DateFormat('MMMM yyyy').format(_month);

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final sum = await api.summary(_ym);
      final list = await api.listTransactions(_ym);

      final bRes = await authedGet(context, '/budgets?month=$_ym');
      if (bRes.statusCode != 200) {
        throw Exception('Budgets failed: ${bRes.statusCode} ${bRes.body}');
      }
      final bList =
          (jsonDecode(bRes.body) as List).cast<Map<String, dynamic>>();

      final parsedTxs = list.map<Tx>((j) => Tx.fromJson(j)).toList();
      final spentByCat = <String, double>{};
      for (final t in parsedTxs) {
        spentByCat.update(t.category, (v) => v + t.amount,
            ifAbsent: () => t.amount);
      }

      final rows = <_BudgetRow>[];
      for (final b in bList) {
        final cat = (b['category'] ?? '').toString();
        final limit = (b['amount'] as num).toDouble();
        final spent = spentByCat[cat] ?? 0.0;
        final remaining = (limit - spent);
        final pct = limit <= 0 ? 0.0 : (spent / limit).clamp(0.0, 1.0);
        rows.add(_BudgetRow(
            category: cat,
            spent: spent,
            limit: limit,
            remaining: remaining,
            pct: pct));
      }

      setState(() {
        summary = sum;
        txs = parsedTxs;
        budgetRows = rows;
      });
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Error: $e')));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final total = summary == null ? null : (summary!['total_spent'] ?? 0);
    final cats = (summary?['top_categories'] as List?) ?? [];

    return Scaffold(
      appBar: AppBar(title: const Text('Dashboard')),
      body: RefreshIndicator(
        onRefresh: _load,
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  SectionCard(
                    title: 'This month',
                    trailing: MonthSwitcher(
                      label: _monthLabel,
                      onPrev: () {
                        setState(() => _month =
                            DateTime(_month.year, _month.month - 1, 1));
                        _load();
                      },
                      onNext: () {
                        setState(() => _month =
                            DateTime(_month.year, _month.month + 1, 1));
                        _load();
                      },
                    ),
                    children: [
                      ListTile(
                        contentPadding: EdgeInsets.zero,
                        title: const Text('Total spent'),
                        trailing: Text(
                          total == null ? '—' : sar(total),
                          style: Theme.of(context).textTheme.headlineSmall,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),

                  SectionCard(
                    title: 'Budgets',
                    children: [
                      if (budgetRows.isEmpty)
                        const Text(
                          'No budgets set for this month yet. Go to Budgets to add one.',
                          style: TextStyle(color: Colors.black54),
                        ),
                      for (final r in budgetRows) ...[
                        _BudgetTile(row: r),
                        const SizedBox(height: 8),
                      ],
                    ],
                  ),
                  const SizedBox(height: 8),

                  if (cats.isNotEmpty)
                    SectionCard(
                      title: 'Where your money went',
                      children: [
                        SizedBox(
                          height: 220,
                          child: PieChart(
                            PieChartData(
                              sectionsSpace: 2,
                              centerSpaceRadius: 36,
                              sections: [
                                for (final row in cats)
                                  PieChartSectionData(
                                    value: (row[1] as num).toDouble(),
                                    title: row[0].toString(),
                                    radius: 70,
                                    titleStyle: const TextStyle(fontSize: 11),
                                  ),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),

                  const SizedBox(height: 8),
                  Text('Recent expenses',
                      style: Theme.of(context).textTheme.titleMedium),
                  for (final t in txs.take(15))
                    Card(
                      child: ListTile(
                        title: Text('${t.category} · ${sar(t.amount)}'),
                        subtitle: Text(
                            '${t.date}${t.merchant != null ? ' · ${t.merchant}' : ''}'),
                      ),
                    ),
                ],
              ),
      ),
    );
  }
}

class _BudgetRow {
  final String category;
  final double spent;
  final double limit;
  final double remaining;
  final double pct;
  _BudgetRow({
    required this.category,
    required this.spent,
    required this.limit,
    required this.remaining,
    required this.pct,
  });
}

class _BudgetTile extends StatelessWidget {
  const _BudgetTile({required this.row});
  final _BudgetRow row;

  @override
  Widget build(BuildContext context) {
    final over = row.remaining < 0;
    final remText = over
        ? 'Over by ${sar(-row.remaining)}'
        : 'Left ${sar(row.remaining)}';

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(child: Text(row.category)),
            Text('${sar(row.spent, zeroDecimals: true)} / '
                '${sar(row.limit, zeroDecimals: true)}'),
          ],
        ),
        const SizedBox(height: 4),
        ClipRRect(
          borderRadius: BorderRadius.circular(8),
          child: LinearProgressIndicator(
            value: row.pct,
            minHeight: 8,
          ),
        ),
        const SizedBox(height: 4),
        Text(remText,
            style: TextStyle(color: over ? Colors.red[700] : Colors.black54)),
      ],
    );
  }
}

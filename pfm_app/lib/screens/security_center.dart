// lib/screens/security_center.dart
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:fl_chart/fl_chart.dart';

import '../services/auth_service.dart';
import '../state/auth_state.dart';

class SecurityCenterScreen extends StatefulWidget {
  const SecurityCenterScreen({super.key});
  @override
  State<SecurityCenterScreen> createState() => _SecurityCenterScreenState();
}

class _SecurityCenterScreenState extends State<SecurityCenterScreen>
    with SingleTickerProviderStateMixin {
  final svc = AuthService();

  bool loading = true;
  List<dynamic> devices = [];
  List<dynamic> logins = [];
  List<dynamic> sessions = [];
  Map<String, dynamic>? _impossibleTravel;
  Map<String, dynamic>? _anomaly;
  Map<String, dynamic>? _metrics; // { series: [...], totals: {...}, devices: {...} }
  List<dynamic> _geo = [];        // [{ts, ip, city, lat, lon, risk, device}]

  // Intelligence
  Map<String, dynamic>? _intel;   // profile
  Map<String, dynamic>? _txScore; // latest scored tx
  Map<String, dynamic>? _loginScore;

  late final TabController _tab;

  @override
  void initState() {
    super.initState();
    _tab = TabController(length: 6, vsync: this); // Intel tab
    _load();
  }

  @override
  void dispose() {
    _tab.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() => loading = true);
    try {
      final token = context.read<AuthState>().token!;
      final d = await svc.listDevices(token);
      final l = await svc.listLogins(token);
      final s = await svc.listSessions(token);
      final it = await svc.impossibleTravel(token);
      final an = await svc.anomalyScore(token);
      final m = await svc.securityMetrics(token);
      final g = await svc.geoLogins(token);
      final iprofile = await svc.intelProfile(token);

      if (!mounted) return;
      setState(() {
        devices = d;
        logins = l;
        sessions = s;
        _impossibleTravel = it;
        _anomaly = an;
        _metrics = m;
        _geo = (g['logins'] as List?) ?? [];
        _intel = iprofile;
      });
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Security load failed: $e')),
      );
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  // small helpers
  String _safeCity(Map<String, dynamic>? m) => (m?['city'] as String?) ?? '—';
  String _safeIp(Map<String, dynamic>? m) => (m?['ip'] as String?) ?? '—';
  T? _asMap<T extends Map>(dynamic v) => v is T ? v : null;

  // Dashboard
  Widget _dashboardTab() {
    final series = (_metrics?['series'] as List?) ?? [];
    final totals = _asMap<Map<String, dynamic>>(_metrics?['totals']) ?? {};
    final devs = _asMap<Map<String, dynamic>>(_metrics?['devices']) ?? {};

    List<FlSpot> _spots(String key) {
      final spots = <FlSpot>[];
      for (var i = 0; i < series.length; i++) {
        final m = series[i] as Map<String, dynamic>;
        spots.add(FlSpot(i.toDouble(), ((m[key] as num?) ?? 0).toDouble()));
      }
      return spots;
    }

    final success = _spots('success');
    final fail = _spots('fail');
    final risky = _spots('risky');

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text('Last 30 days', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: SizedBox(
                height: 200,
                child: LineChart(
                  LineChartData(
                    minY: 0,
                    lineTouchData: const LineTouchData(enabled: true),
                    gridData: const FlGridData(show: true),
                    titlesData: const FlTitlesData(
                      leftTitles: AxisTitles(sideTitles: SideTitles(showTitles: true, reservedSize: 28)),
                      bottomTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                      rightTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                      topTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                    ),
                    borderData: FlBorderData(show: true),
                    lineBarsData: [
                      LineChartBarData(spots: success, isCurved: true),
                      LineChartBarData(spots: fail, isCurved: true),
                      LineChartBarData(spots: risky, isCurved: true),
                    ],
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 12,
            children: [
              _metricChip('Success', (totals['success'] ?? 0).toString()),
              _metricChip('Failed', (totals['fail'] ?? 0).toString()),
              _metricChip('Risky', (totals['risky'] ?? 0).toString()),
              _metricChip('Trusted devices', '${devs['trusted'] ?? 0}/${devs['total'] ?? 0}'),
            ],
          ),
          const SizedBox(height: 16),
          Text('Recent login locations', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          for (final e in _geo)
            Card(
              child: ListTile(
                leading: const Icon(Icons.place_outlined),
                title: Text('${e['city'] ?? '—'}  ·  ${e['ip'] ?? '—'}'),
                subtitle: Text('${e['ts'] ?? ''}\n'
                    'device: ${e['device'] ?? '—'} · risk ${e['risk'] ?? 0}'),
              ),
            ),
        ],
      ),
    );
  }

  Widget _metricChip(String label, String value) {
    return Chip(
      label: Text('$label: $value'),
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
    );
  }

  // Overview
  Widget _overviewTab() {
    final imp = _impossibleTravel ?? const {};
    final enough = imp['enough_data'] == true;
    final from = _asMap<Map<String, dynamic>>(imp['from']);
    final to = _asMap<Map<String, dynamic>>(imp['to']);

    final distance = imp['distance_km']?.toString() ?? '—';
    final hours = imp['hours_between']?.toString() ?? '—';
    final speed = imp['speed_kmh']?.toString() ?? '—';
    final flagged = imp['flagged'] == true;

    final an = _anomaly ?? const {};
    final anEnough = an['enough_data'] == true;
    final anScore = (an['score'] as num?)?.toInt() ?? 0;
    final anLast = (an['last_amount'] as num?)?.toDouble();
    final anMed = (an['median'] as num?)?.toDouble();

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: ListTile(
            title: const Text('Impossible travel'),
            subtitle: enough
                ? Text(
                    '${_safeCity(from)} (${_safeIp(from)}) → ${_safeCity(to)} (${_safeIp(to)})\n'
                    'distance: $distance km · hours: $hours · speed: $speed km/h',
                  )
                : const Text('Not enough data yet (need 2+ successful logins)'),
            trailing: enough
                ? Chip(
                    label: Text(flagged ? 'FLAGGED' : 'OK'),
                    backgroundColor: flagged ? Colors.red.withOpacity(0.15) : null,
                    labelStyle: TextStyle(color: flagged ? Colors.red : null),
                  )
                : null,
          ),
        ),
        const SizedBox(height: 12),
        Card(
          child: ListTile(
            title: const Text('Transaction anomaly score'),
            subtitle: anEnough
                ? Text(
                    'last: ${anLast?.toStringAsFixed(2) ?? '—'} · '
                    'median: ${anMed?.toStringAsFixed(2) ?? '—'}',
                  )
                : const Text('Not enough data yet'),
            trailing: CircleAvatar(
              radius: 16,
              child: Text('$anScore'),
            ),
          ),
        ),
        const SizedBox(height: 12),
        FilledButton.tonalIcon(
          onPressed: _showExportDialog,
          icon: const Icon(Icons.ios_share),
          label: const Text('Export audit (NDJSON)'),
        ),
      ],
    );
  }

  Widget _devicesTab() {
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          for (final d in devices)
            Card(
              child: ListTile(
                title: Text(d['label']?.toString() ?? '(unknown device)'),
                subtitle: Text(
                  'hash: ${d['device_hash']}\n'
                  'first seen: ${d['first_seen']}\n'
                  'last seen: ${d['last_seen']}\n'
                  'last ip: ${d['last_ip'] ?? '—'}',
                ),
                trailing: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    if (d['trusted'] == true)
                      const Chip(label: Text('Trusted'))
                    else
                      TextButton(
                        onPressed: () async {
                          try {
                            final token = context.read<AuthState>().token!;
                            await svc.trustDevice(token, d['device_hash']);
                            await _load();
                          } catch (e) {
                            if (!mounted) return;
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text('Trust failed: $e')),
                            );
                          }
                        },
                        child: const Text('Trust'),
                      ),
                    const SizedBox(height: 4),
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        TextButton(
                          onPressed: () async {
                            try {
                              final token = context.read<AuthState>().token!;
                              await svc.bindDevice(token, d['device_hash']);
                              if (!mounted) return;
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: Text('Device bound. Future logins will auto-trust.')),
                              );
                            } catch (e) {
                              if (!mounted) return;
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text('Bind failed: $e')),
                              );
                            }
                          },
                          child: const Text('Bind'),
                        ),
                        TextButton(
                          onPressed: () async {
                            try {
                              final token = context.read<AuthState>().token!;
                              await svc.unbindDevice(token, d['device_hash']);
                              if (!mounted) return;
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: Text('Device unbound.')),
                              );
                            } catch (e) {
                              if (!mounted) return;
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(content: Text('Unbind failed: $e')),
                              );
                            }
                          },
                          child: const Text('Unbind'),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _sessionsTab() {
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: sessions.length,
        itemBuilder: (_, i) {
          final s = sessions[i] as Map<String, dynamic>;
          return Card(
            child: ListTile(
              leading: Icon(s['revoked'] == true ? Icons.block : Icons.computer),
              title: Text('Session ${s['session_id']}'),
              subtitle: Text(
                'created: ${s['created_at']}\n'
                'last seen: ${s['last_seen']}\n'
                'ip: ${s['ip'] ?? '—'}\n'
                'device: ${s['device_hash'] ?? '—'}',
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _loginsTab() {
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: logins.length,
        itemBuilder: (_, i) {
          final e = logins[i] as Map<String, dynamic>;
          final ok = e['success'] == true;
          final risk = (e['risk_score'] as num?)?.toInt() ?? 0;
          return Card(
            child: ListTile(
              leading: Icon(
                ok ? Icons.check_circle : Icons.error,
                color: ok
                    ? (risk >= 60 ? Colors.orange : null)
                    : Colors.red,
              ),
              title: Text('${e['ts']}  ·  risk $risk'),
              subtitle: Text(
                'ip: ${e['ip'] ?? '—'}\n'
                'reason: ${e['risk_reason'] ?? '—'}\n'
                'device: ${e['device_hash'] ?? '—'}',
              ),
            ),
          );
        },
      ),
    );
  }

  // Intelligence UI
  Widget _intelTab() {
    final prof = _intel ?? const {};
    final hours = (prof['login_hours_hist'] as Map?)?.cast<String, dynamic>() ?? {};
    final cities = (prof['login_cities'] as Map?)?.cast<String, dynamic>() ?? {};
    final devtrust = (prof['device_trust'] as Map?)?.cast<String, dynamic>() ?? {};
    final catStats = (prof['tx_category_stats'] as Map?)?.cast<String, dynamic>() ?? {};

    final hourSpots = List.generate(24, (i) {
      final key = '$i';
      final v = (hours[key] as num?)?.toDouble() ?? 0.0;
      return BarChartGroupData(x: i, barRods: [BarChartRodData(toY: v)]);
    });

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Text('Learned profile', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: SizedBox(
                height: 180,
                child: BarChart(
                  BarChartData(
                    barGroups: hourSpots,
                    titlesData: const FlTitlesData(
                      leftTitles: AxisTitles(sideTitles: SideTitles(showTitles: true, reservedSize: 28)),
                      rightTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                      topTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                      bottomTitles: AxisTitles(sideTitles: SideTitles(showTitles: false)),
                    ),
                    gridData: const FlGridData(show: true),
                    borderData: FlBorderData(show: true),
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final e in cities.entries) Chip(label: Text('${e.key}: ${e.value}')),
            ],
          ),
          const SizedBox(height: 8),
          Text('Device trust', style: Theme.of(context).textTheme.titleSmall),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final e in devtrust.entries)
                Chip(
                  avatar: Icon(e.value == true ? Icons.verified_user : Icons.device_unknown, size: 18),
                  label: Text('${e.key.substring(0, 8)}…  ${e.value == true ? 'trusted' : 'untrusted'}'),
                ),
            ],
          ),
          const SizedBox(height: 8),
          ExpansionTile(
            title: const Text('Category stats (median/MAD approx)'),
            children: [
              for (final entry in catStats.entries)
                ListTile(
                  dense: true,
                  title: Text(entry.key),
                  subtitle: Text(entry.value.toString()),
                ),
            ],
          ),
          const SizedBox(height: 16),
          _TxScorer(onScore: (m) => setState(() => _txScore = m)),
          if (_txScore != null)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Card(
                child: ListTile(
                  title: Text('TX score: ${_txScore!['total']}'),
                  subtitle: Text('parts: ${(_txScore!['parts'] as List?)?.join(', ') ?? ''}\n'
                      'details: ${_txScore!['details']}'),
                ),
              ),
            ),
          const SizedBox(height: 12),
          _LoginScorer(onScore: (m) => setState(() => _loginScore = m)),
          if (_loginScore != null)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Card(
                child: ListTile(
                  title: Text('Login score: ${_loginScore!['total']}'),
                  subtitle: Text('parts: ${(_loginScore!['parts'] as List?)?.join(', ') ?? ''}\n'
                      'details: ${_loginScore!['details']}'),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Future<void> _showExportDialog() async {
    try {
      final token = context.read<AuthState>().token!;
      final ndjson = await svc.exportAuditNdjson(token);
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Audit export (NDJSON)'),
          content: SizedBox(
            width: 600,
            child: SingleChildScrollView(
              child: SelectableText(
                ndjson,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: ndjson));
                Navigator.pop(ctx);
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Copied to clipboard')),
                );
              },
              child: const Text('Copy'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Close'),
            ),
          ],
        ),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Export failed: $e')));
    }
  }

  @override
  Widget build(BuildContext context) {
    if (loading) {
      return const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
    }
    return Scaffold(
      appBar: AppBar(
        title: const Text('Security Center'),
        bottom: TabBar(
          controller: _tab,
          isScrollable: true,
          tabs: const [
            Tab(text: 'Overview'),
            Tab(text: 'Dashboard'),
            Tab(text: 'Devices'),
            Tab(text: 'Sessions'),
            Tab(text: 'Logins'),
            Tab(text: 'Intel'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tab,
        children: [
          _overviewTab(),
          _dashboardTab(),
          _devicesTab(),
          _sessionsTab(),
          _loginsTab(),
          _intelTab(),
        ],
      ),
    );
  }
}

// ---- small scoring widgets ----
class _TxScorer extends StatefulWidget {
  const _TxScorer({required this.onScore});
  final void Function(Map<String, dynamic>) onScore;
  @override
  State<_TxScorer> createState() => _TxScorerState();
}

class _TxScorerState extends State<_TxScorer> {
  final _amount = TextEditingController(text: '250');
  final _category = TextEditingController(text: 'GROCERIES');
  final _currency = TextEditingController(text: 'SAR');
  final _merchant = TextEditingController(text: '');
  bool _busy = false;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Score hypothetical transaction',
                style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              children: [
                SizedBox(
                  width: 120,
                  child: TextField(
                    controller: _amount,
                    decoration: const InputDecoration(labelText: 'Amount'),
                    keyboardType: TextInputType.number,
                  ),
                ),
                SizedBox(
                  width: 160,
                  child: TextField(
                    controller: _category,
                    decoration: const InputDecoration(labelText: 'Category'),
                  ),
                ),
                SizedBox(
                  width: 100,
                  child: TextField(
                    controller: _currency,
                    decoration: const InputDecoration(labelText: 'Currency'),
                  ),
                ),
                SizedBox(
                  width: 180,
                  child: TextField(
                    controller: _merchant,
                    decoration: const InputDecoration(labelText: 'Merchant (opt)'),
                  ),
                ),
                FilledButton(
                  onPressed: _busy
                      ? null
                      : () async {
                          setState(() => _busy = true);
                          try {
                            final token = context.read<AuthState>().token!;
                            final res = await AuthService().intelScoreTx(
                              token,
                              amount: double.tryParse(_amount.text) ?? 0,
                              currency: _currency.text.trim().toUpperCase(),
                              category: _category.text.trim().toUpperCase(),
                              merchant: _merchant.text.trim().isEmpty
                                  ? null
                                  : _merchant.text.trim(),
                            );
                            widget.onScore(res);
                          } catch (e) {
                            if (!mounted) return;
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text('Score failed: $e')),
                            );
                          } finally {
                            if (mounted) setState(() => _busy = false);
                          }
                        },
                  child: _busy
                      ? const SizedBox(
                          width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Score'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _LoginScorer extends StatefulWidget {
  const _LoginScorer({required this.onScore});
  final void Function(Map<String, dynamic>) onScore;
  @override
  State<_LoginScorer> createState() => _LoginScorerState();
}

class _LoginScorerState extends State<_LoginScorer> {
  final _ip = TextEditingController(text: '127.0.0.1');
  final _device = TextEditingController(text: '');
  final _ua = TextEditingController(text: '');
  bool _busy = false;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Score hypothetical login',
                style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              children: [
                SizedBox(
                  width: 180,
                  child: TextField(
                    controller: _ip,
                    decoration: const InputDecoration(labelText: 'IP (opt)'),
                  ),
                ),
                SizedBox(
                  width: 240,
                  child: TextField(
                    controller: _device,
                    decoration: const InputDecoration(labelText: 'Device hash (opt)'),
                  ),
                ),
                SizedBox(
                  width: 260,
                  child: TextField(
                    controller: _ua,
                    decoration: const InputDecoration(labelText: 'User-Agent (opt)'),
                  ),
                ),
                FilledButton(
                  onPressed: _busy
                      ? null
                      : () async {
                          setState(() => _busy = true);
                          try {
                            final token = context.read<AuthState>().token!;
                            final res = await AuthService().intelScoreLogin(
                              token,
                              ip: _ip.text.trim().isEmpty ? null : _ip.text.trim(),
                              deviceHash: _device.text.trim().isEmpty ? null : _device.text.trim(),
                              userAgent: _ua.text.trim().isEmpty ? null : _ua.text.trim(),
                            );
                            widget.onScore(res);
                          } catch (e) {
                            if (!mounted) return;
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text('Score failed: $e')),
                            );
                          } finally {
                            if (mounted) setState(() => _busy = false);
                          }
                        },
                  child: _busy
                      ? const SizedBox(
                          width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Score'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

// lib/utils/format.dart
import 'package:intl/intl.dart';

// Format a number as Saudi Riyal.
String sar(num value, {bool zeroDecimals = false}) {
  final f = NumberFormat.currency(
    locale: 'en_US',
    symbol: 'SAR ',
    decimalDigits: zeroDecimals ? 0 : 2,
  );
  return f.format(value);
}

String sarCompact(num value) {
  final abs = value.abs();
  String s;
  if (abs >= 1e9) {
    s = '${(value / 1e9).toStringAsFixed(1)}B';
  } else if (abs >= 1e6) {
    s = '${(value / 1e6).toStringAsFixed(1)}M';
  } else if (abs >= 1e3) {
    s = '${(value / 1e3).toStringAsFixed(1)}K';
  } else {
    s = value.toStringAsFixed(0);
  }
  // strip trailing .0
  if (s.endsWith('.0K') || s.endsWith('.0M') || s.endsWith('.0B')) {
    s = s.replaceAll('.0', '');
  }
  return 'SAR $s';
}

// lib/ui/theme.dart
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

ThemeData buildAppTheme(Brightness b) {
  final base = ThemeData(
    colorSchemeSeed: const Color(0xFF5E81F4),
    useMaterial3: true,
    brightness: b,
  );

  final textTheme = GoogleFonts.interTextTheme(base.textTheme);

  return base.copyWith(
    textTheme: textTheme,
    inputDecorationTheme: const InputDecorationTheme(
      border: OutlineInputBorder(),
      filled: true,
      fillColor: Colors.transparent,
    ),
    cardTheme: const CardThemeData(
      elevation: 0,
      margin: EdgeInsets.symmetric(vertical: 6),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.all(Radius.circular(16))),
    ),
    chipTheme: base.chipTheme.copyWith(
      shape: StadiumBorder(side: BorderSide(color: base.colorScheme.outlineVariant)),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
    ),
    listTileTheme: const ListTileThemeData(contentPadding: EdgeInsets.symmetric(horizontal: 16, vertical: 6)),
    snackBarTheme: base.snackBarTheme.copyWith(behavior: SnackBarBehavior.floating),
  );
}

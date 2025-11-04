// test/widget_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:pfm_app/main.dart';

void main() {
  testWidgets('PFM app boots and shows NavigationBar', (WidgetTester tester) async {
    await tester.pumpWidget(const PFMApp());
    await tester.pumpAndSettle();

    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.text('Dashboard'), findsOneWidget);
    expect(find.text('Settings'), findsOneWidget);
  });
}

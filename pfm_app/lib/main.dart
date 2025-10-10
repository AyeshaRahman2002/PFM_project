// lib/main.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'state/auth_state.dart';

import 'screens/dashboard_screen.dart';
import 'screens/add_expense_screen.dart';
import 'screens/budgets_screen.dart';
import 'screens/goals_screen.dart';
import 'screens/settings_screen.dart';
import 'ui/theme.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final auth = AuthState();
  await auth.loadFromStorage();          // restore saved session (if any)
  runApp(
    ChangeNotifierProvider<AuthState>.value(
      value: auth,
      child: const PFMApp(),
    ),
  );
}

class PFMApp extends StatelessWidget {
  const PFMApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'PFM',
      theme: buildAppTheme(Brightness.light),
      darkTheme: buildAppTheme(Brightness.dark),
      themeMode: ThemeMode.system,
      home: const RootNav(),
    );
  }
}

class RootNav extends StatefulWidget {
  const RootNav({super.key});
  @override State<RootNav> createState() => _RootNavState();
}

class _RootNavState extends State<RootNav> {
  int idx = 0;
  final pages = const [
    DashboardScreen(),
    AddExpenseScreen(),
    BudgetsScreen(),
    GoalsScreen(),
    SettingsScreen(),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: pages[idx],
      bottomNavigationBar: NavigationBar(
        selectedIndex: idx,
        onDestinationSelected: (i) => setState(() => idx = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.dashboard_outlined), selectedIcon: Icon(Icons.dashboard), label: 'Dashboard'),
          NavigationDestination(icon: Icon(Icons.add_circle_outline), selectedIcon: Icon(Icons.add_circle), label: 'Add'),
          NavigationDestination(icon: Icon(Icons.account_balance_wallet_outlined), selectedIcon: Icon(Icons.account_balance_wallet), label: 'Budgets'),
          NavigationDestination(icon: Icon(Icons.flag_outlined), selectedIcon: Icon(Icons.flag), label: 'Goals'),
          NavigationDestination(icon: Icon(Icons.settings_outlined), selectedIcon: Icon(Icons.settings), label: 'Settings'),
        ],
      ),
    );
  }
}

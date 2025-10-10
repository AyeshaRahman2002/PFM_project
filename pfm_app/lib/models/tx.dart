// models/tx.dart
class Tx {
  final int id;
  final double amount;
  final String category;
  final String date;
  final String? merchant;
  final String? notes;
  Tx({required this.id,required this.amount,required this.category,required this.date,this.merchant,this.notes});
  factory Tx.fromJson(Map<String,dynamic> j)=>Tx(
    id:j['id'], amount:(j['amount'] as num).toDouble(),
    category:j['category'], date:j['date'],
    merchant:j['merchant'], notes:j['notes']);
}

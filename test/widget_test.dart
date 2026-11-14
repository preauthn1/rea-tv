import 'package:flutter_test/flutter_test.dart';
import 'package:rea_tv/main.dart';

void main() {
  testWidgets('renders the Android TV investigation workspace', (tester) async {
    await tester.pumpWidget(const ReaTvApp());
    await tester.pump();

    expect(find.text('调查工作台'), findsWidgets);
    expect(find.text('开始一次有界分析'), findsOneWidget);
    expect(find.text('后端连接'), findsOneWidget);
  });
}

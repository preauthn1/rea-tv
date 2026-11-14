import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

void main() => runApp(const ReaTvApp());

class EvidenceRecord {
  const EvidenceRecord({required this.id, required this.operation, required this.target, required this.summary, required this.confidence, required this.authority, required this.limitations, this.location});
  final String id, operation, target, summary, confidence, authority;
  final List<String> limitations;
  final String? location;
  factory EvidenceRecord.fromJson(Map<String, dynamic> j) => EvidenceRecord(
        id: j['evidence_id'] as String? ?? 'ev-unknown',
        operation: j['operation'] as String? ?? 'unknown operation',
        target: ((j['subject'] as Map?)?['name'] as String?) ?? 'unknown target',
        summary: _readSummary(j['normalized_result']),
        confidence: j['confidence'] as String? ?? 'inferred',
        authority: j['authority'] as String? ?? 'analyst-inference',
        limitations: [for (final x in (j['limitations'] as List? ?? const [])) '$x'],
        location: ((j['locations'] as List?)?.isNotEmpty ?? false) ? '${(j['locations'] as List).first}' : null,
      );
  static String _readSummary(dynamic result) {
    if (result is Map && result['summary'] != null) return '${result['summary']}';
    final text = const JsonEncoder.withIndent('  ').convert(result ?? {});
    return text.length > 900 ? '${text.substring(0, 900)}…' : text;
  }
}

class ReaBackend {
  ReaBackend(this.baseUrl);
  final String baseUrl;
  Uri _uri(String path, [Map<String, String>? query]) => Uri.parse('$baseUrl/${path.replaceFirst(RegExp(r'^/+'), '')}').replace(queryParameters: query);
  Future<List<String>> capabilities() async {
    final r = await http.get(_uri('/api/capabilities'));
    _check(r);
    final data = jsonDecode(r.body);
    return [for (final x in (data['families'] as List? ?? const [])) '${x['name'] ?? x}'];
  }
  Future<List<EvidenceRecord>> evidence() async {
    final r = await http.get(_uri('/api/evidence', {'limit': '50'}));
    _check(r);
    final data = jsonDecode(r.body) as List;
    return data.map((x) => EvidenceRecord.fromJson(x as Map<String, dynamic>)).toList();
  }
  Future<void> submit(String operation, String target) async {
    final r = await http.post(_uri('/api/analyses'), headers: {'content-type': 'application/json'}, body: jsonEncode({'operation': operation, 'target': target}));
    _check(r);
  }
  static void _check(http.Response r) { if (r.statusCode < 200 || r.statusCode >= 300) throw Exception('Backend HTTP ${r.statusCode}: ${r.body}'); }
}

class ReaTvApp extends StatelessWidget {
  const ReaTvApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        debugShowCheckedModeBanner: false,
        title: 'REA TV',
        theme: ThemeData(
          brightness: Brightness.dark,
          scaffoldBackgroundColor: const Color(0xff080b12),
          colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xff41d6a3), brightness: Brightness.dark),
          focusColor: const Color(0xffb5ffe5),
          cardTheme: const CardThemeData(color: Color(0xff121924), margin: EdgeInsets.zero),
        ),
        home: const ReaHomePage(),
      );
}

class ReaHomePage extends StatefulWidget {
  const ReaHomePage({super.key});
  @override State<ReaHomePage> createState() => _ReaHomePageState();
}

class _ReaHomePageState extends State<ReaHomePage> {
  final _backendCtrl = TextEditingController(text: 'http://192.0.2.2:8787');
  final _targetCtrl = TextEditingController();
  final _scopeFocus = FocusNode();
  final _targetFocus = FocusNode();
  List<String> families = [];
  List<EvidenceRecord> records = [];
  String selectedFamily = 'Android APK';
  String? error;
  bool loading = false;
  int tab = 0;

  @override void initState() { super.initState(); _loadBackend(); }
  @override void dispose() { _backendCtrl.dispose(); _targetCtrl.dispose(); _scopeFocus.dispose(); _targetFocus.dispose(); super.dispose(); }
  Future<void> _loadBackend() async { final p = await SharedPreferences.getInstance(); final v = p.getString('rea_backend'); if (v != null) _backendCtrl.text = v; }
  ReaBackend get _api => ReaBackend(_backendCtrl.text.trim());
  Future<void> _refresh() async { setState(() { loading = true; error = null; }); try { families = await _api.capabilities(); records = await _api.evidence(); } catch (e) { error = '$e'; } if (mounted) setState(() => loading = false); }
  Future<void> _saveBackend() async { final p = await SharedPreferences.getInstance(); await p.setString('rea_backend', _backendCtrl.text.trim()); await _refresh(); }
  Future<void> _run() async { if (_targetCtrl.text.trim().isEmpty) { setState(() => error = '先输入目标路径或后端可见的目标标识。'); return; } setState(() { loading = true; error = null; }); try { await _api.submit(selectedFamily, _targetCtrl.text.trim()); await _refresh(); } catch (e) { setState(() => error = '$e'); } }

  @override
  Widget build(BuildContext context) => FocusTraversalGroup(child: Shortcuts(shortcuts: const {SingleActivator(LogicalKeyboardKey.select): ActivateIntent()}, child: Actions(actions: {ActivateIntent: CallbackAction<ActivateIntent>(onInvoke: (_) { _refresh(); return null; })}, child: Scaffold(body: SafeArea(child: Row(children: [_nav(), Expanded(child: _page())]))))));
  Widget _nav() => Container(
        width: 280,
        padding: const EdgeInsets.all(26),
        decoration: const BoxDecoration(
          color: Color(0xff0e141e),
          border: Border(right: BorderSide(color: Color(0xff26313c))),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('REA', style: TextStyle(fontSize: 34, fontWeight: FontWeight.w900, letterSpacing: 3, color: Color(0xff8dffe0))),
            const Text('Reverse Engineer Anything', style: TextStyle(color: Color(0xff8995a7))),
            const SizedBox(height: 48),
            const Text('工作区', style: TextStyle(color: Color(0xff8995a7))),
            const SizedBox(height: 12),
            _NavButton(icon: Icons.radar, label: '调查工作台', selected: tab == 0, onTap: () => setState(() => tab = 0)),
            _NavButton(icon: Icons.fact_check, label: '证据 ledger', selected: tab == 1, onTap: () => setState(() => tab = 1)),
            _NavButton(icon: Icons.settings_outlined, label: '后端连接', selected: tab == 2, onTap: () => setState(() => tab = 2)),
            const Spacer(),
            const Text('Evidence-first / read-only TV client', style: TextStyle(color: Color(0xff627080), fontSize: 12)),
          ],
        ),
      );
  Widget _page() { if (tab == 1) return _evidencePage(); if (tab == 2) return _settingsPage(); return _workspacePage(); }
  Widget _workspacePage() => Padding(padding: const EdgeInsets.fromLTRB(36, 30, 36, 24), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text('调查工作台', style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w800)), const SizedBox(height: 8), const Text('选择能力、提交目标、在同一屏查看结果和限制。', style: TextStyle(color: Color(0xff9ba8b7))), const SizedBox(height: 28), Row(crossAxisAlignment: CrossAxisAlignment.start, children: [Expanded(child: _operationPanel()), const SizedBox(width: 22), Expanded(child: _statusPanel())]), const SizedBox(height: 24), Expanded(child: _recentEvidence())]));
  Widget _operationPanel() => Card(
        child: Padding(
          padding: const EdgeInsets.all(22),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('开始一次有界分析', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700)),
              const SizedBox(height: 18),
              DropdownButtonFormField<String>(
                isExpanded: true,
                initialValue: selectedFamily,
                items: [selectedFamily, ...families.where((x) => x != selectedFamily)].map((x) => DropdownMenuItem(value: x, child: Text(x, overflow: TextOverflow.ellipsis))).toList(),
                onChanged: (v) => setState(() => selectedFamily = v ?? selectedFamily),
                decoration: const InputDecoration(labelText: '能力族', border: OutlineInputBorder()),
              ),
              const SizedBox(height: 14),
              TextField(focusNode: _targetFocus, controller: _targetCtrl, decoration: const InputDecoration(labelText: '目标路径或目标标识', hintText: '/targets/sample.apk', border: OutlineInputBorder())),
              const SizedBox(height: 18),
              Wrap(spacing: 14, runSpacing: 10, children: [
                FilledButton.icon(onPressed: loading ? null : _run, icon: const Icon(Icons.play_arrow), label: const Text('提交分析')),
                OutlinedButton.icon(onPressed: loading ? null : _refresh, icon: const Icon(Icons.refresh), label: const Text('刷新证据')),
              ]),
            ],
          ),
        ),
      );
  Widget _statusPanel() => Card(child: Padding(padding: const EdgeInsets.all(22), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [const Text('状态', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700)), const SizedBox(height: 18), _Metric(label: '后端', value: _backendCtrl.text.isEmpty ? '未配置' : '已配置', color: const Color(0xff8dffe0)), _Metric(label: '能力族', value: '${families.length} 个'), _Metric(label: '证据记录', value: '${records.length} 条'), if (loading) const Padding(padding: EdgeInsets.only(top: 12), child: LinearProgressIndicator()), if (error != null) Padding(padding: const EdgeInsets.only(top: 14), child: Text(error!, style: const TextStyle(color: Colors.orangeAccent))) ])));
  Widget _recentEvidence() => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [const Text('最近证据', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700)), const SizedBox(height: 12), Expanded(child: records.isEmpty ? const Center(child: Text('还没有证据。提交一次分析后，结果会保留在这里。', style: TextStyle(color: Color(0xff8d99a8)))) : ListView.separated(itemCount: records.length, separatorBuilder: (_, __) => const SizedBox(height: 10), itemBuilder: (_, i) => _EvidenceTile(record: records[i]))) ]);
  Widget _evidencePage() => Padding(padding: const EdgeInsets.all(36), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text('证据 ledger', style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w800)), const SizedBox(height: 8), const Text('每条结论都保留来源、置信度、权威级别和限制。', style: TextStyle(color: Color(0xff9ba8b7))), const SizedBox(height: 24), Expanded(child: _recentEvidence())]));
  Widget _settingsPage() => Padding(
        padding: const EdgeInsets.all(36),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('后端连接', style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w800)),
            const SizedBox(height: 18),
            SizedBox(
              width: 680,
              child: TextField(
                controller: _backendCtrl,
                focusNode: _scopeFocus,
                decoration: const InputDecoration(labelText: 'REA backend URL', hintText: 'http://host:8787', border: OutlineInputBorder()),
              ),
            ),
            const SizedBox(height: 14),
            FilledButton.icon(onPressed: _saveBackend, icon: const Icon(Icons.link), label: const Text('保存并连接')),
            const SizedBox(height: 24),
            const Text('Android TV 客户端不直接执行 APK、二进制或 shell；这些动作由受控后端执行。', style: TextStyle(color: Color(0xff9ba8b7))),
          ],
        ),
      );
}

class _NavButton extends StatelessWidget {
  const _NavButton({required this.icon, required this.label, required this.selected, required this.onTap});
  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: Material(
          color: Colors.transparent,
          child: ListTile(
            selected: selected,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
            leading: Icon(icon, color: selected ? const Color(0xff8dffe0) : null),
            title: Text(label),
            onTap: onTap,
          ),
        ),
      );
}
class _Metric extends StatelessWidget { const _Metric({required this.label, required this.value, this.color}); final String label, value; final Color? color; @override Widget build(BuildContext context) => Padding(padding: const EdgeInsets.only(bottom: 14), child: Row(children: [Expanded(child: Text(label, style: const TextStyle(color: Color(0xff8d99a8)))), Text(value, style: TextStyle(fontWeight: FontWeight.w700, color: color))])); }
class _EvidenceTile extends StatelessWidget {
  const _EvidenceTile({required this.record});
  final EvidenceRecord record;
  @override
  Widget build(BuildContext context) => Card(
        child: ListTile(
          leading: const CircleAvatar(
            backgroundColor: Color(0xff173d36),
            child: Icon(Icons.verified_outlined, color: Color(0xff8dffe0)),
          ),
          title: Text(record.operation),
          subtitle: Text('${record.target}\n${record.summary}', maxLines: 3, overflow: TextOverflow.ellipsis),
          trailing: Text(record.confidence, style: const TextStyle(color: Color(0xffffd479))),
        ),
      );
}

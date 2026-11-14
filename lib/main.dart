import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const _mihomoChannel = MethodChannel('io.rea.rea_tv/mihomo');
const mihomoVersion = 'v1.19.34';
const mihomoAssetUrl = 'https://github.com/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-android-arm64-v8-v1.19.34.gz';
const mihomoAssetSha256 = '48a71fc6a68e2909587176e0ab7185d8f2fac298fa96ccdacf30ea86ab2359b5';

Future<Map<String, dynamic>> _mihomoNative(String method, [Map<String, Object?> args = const {}]) async => Map<String, dynamic>.from((await _mihomoChannel.invokeMapMethod<String, dynamic>(method, args)) ?? const {});


class MihomoProxy {
  const MihomoProxy({required this.name, required this.type, this.alive, this.delay, this.all = const [], this.now});
  final String name, type;
  final bool? alive;
  final int? delay;
  final List<String> all;
  final String? now;
  bool get selectable => type == 'Selector' && all.isNotEmpty;
  factory MihomoProxy.fromJson(Map<String, dynamic> j) => MihomoProxy(
        name: '${j['name'] ?? ''}',
        type: '${j['type'] ?? ''}',
        alive: j['alive'] as bool?,
        delay: (j['delay'] as num?)?.toInt(),
        all: [for (final x in (j['all'] as List? ?? const [])) '$x'],
        now: j['now'] as String?,
      );
}

class AnalysisJob {
  const AnalysisJob({required this.id, required this.operation, required this.target, required this.status, this.message});
  final String id, operation, target, status;
  final String? message;
  factory AnalysisJob.fromJson(Map<String, dynamic> j) => AnalysisJob(
        id: '${j['analysis_id'] ?? j['id'] ?? 'unknown'}',
        operation: '${j['operation'] ?? ''}',
        target: '${j['target'] ?? ''}',
        status: '${j['status'] ?? 'unknown'}',
        message: j['message'] as String?,
      );
}

class EvidenceRecord {
  const EvidenceRecord({required this.id, required this.operation, required this.target, required this.summary, required this.confidence, required this.authority, required this.limitations, this.location, this.rawResult});
  final String id, operation, target, summary, confidence, authority;
  final List<String> limitations;
  final String? location;
  final dynamic rawResult;
  factory EvidenceRecord.fromJson(Map<String, dynamic> j) => EvidenceRecord(
        id: j['evidence_id'] as String? ?? 'ev-unknown',
        operation: j['operation'] as String? ?? 'unknown operation',
        target: ((j['subject'] as Map?)?['name'] as String?) ?? 'unknown target',
        summary: _readSummary(j['normalized_result']),
        confidence: j['confidence'] as String? ?? 'inferred',
        authority: j['authority'] as String? ?? 'analyst-inference',
        limitations: [for (final x in (j['limitations'] as List? ?? const [])) '$x'],
        location: ((j['locations'] as List?)?.isNotEmpty ?? false) ? '${(j['locations'] as List).first}' : null,
        rawResult: j['normalized_result'],
      );
  static String _readSummary(dynamic result) {
    if (result is Map && result['summary'] != null) return '${result['summary']}';
    final text = const JsonEncoder.withIndent('  ').convert(result ?? {});
    return text.length > 900 ? '${text.substring(0, 900)}…' : text;
  }
}

const defaultCapabilityFamilies = <String>[
  'mihomo node management',
  'Android APK',
  'Flutter AOT',
  'Native binary',
  'JavaScript / Electron',
  '.NET managed code',
  'Firmware',
  'Network capture',
  'Evidence ledger',
];

const defaultOperationsByFamily = <String, List<String>>{
  'Android APK': ['inspect_android_package', 'search_android_classes', 'inspect_android_class', 'inspect_android_method', 'trace_android_references', 'inspect_android_jni_bindings'],
  'Flutter AOT': ['identify_flutter_build', 'inspect_dart_aot'],
  'Native binary': ['binary_overview', 'inspect_binary_layout', 'inspect_native_exports', 'inspect_binary_hardening', 'search_bytes', 'inspect_native_load_image'],
  'JavaScript / Electron': ['analyze_javascript_application', 'inspect_electron_fuses', 'trace_application_feature'],
  '.NET managed code': ['inspect_managed_artifact', 'inspect_managed_members', 'project_managed_application_graph'],
  'Firmware': ['inspect_firmware_regions', 'extract_firmware'],
  'Network capture': ['inspect_pcap_client', 'inspect_pcap_capture', 'inspect_web_network_capture'],
  'Evidence ledger': ['inspect_evidence_bundle', 'inspect_analysis_view'],
};

const operationParameterTemplates = <String, String>{
  'inspect_android_package': '{}',
  'search_android_classes': '{"query":""}',
  'inspect_android_class': '{"class_name":"com.example.MainActivity"}',
  'inspect_android_method': '{"class_name":"com.example.MainActivity","method_name":"onCreate"}',
  'trace_android_references': '{"class_name":"com.example.MainActivity","method_name":"onCreate"}',
  'inspect_android_jni_bindings': '{"query":{"class_name":"com.example.NativeBridge","abis":["arm64-v8a"]}}',
  'identify_flutter_build': '{}',
  'inspect_dart_aot': '{"abi":"arm64-v8a"}',
  'search_bytes': '{"pattern":"48 8B ?? ??"}',
  'inspect_native_load_image': '{}',
  'binary_overview': '{}',
  'inspect_binary_layout': '{}',
  'inspect_native_exports': '{}',
  'inspect_binary_hardening': '{}',
  'analyze_javascript_application': '{}',
  'inspect_electron_fuses': '{}',
  'trace_application_feature': '{"feature":"search"}',
  'inspect_managed_artifact': '{}',
  'inspect_managed_members': '{"type_names":["Example.Namespace.Type"]}',
  'project_managed_application_graph': '{}',
  'inspect_firmware_regions': '{}',
  'extract_firmware': '{"range":{"offset":0,"length":4096}}',
  'inspect_pcap_client': '{}',
  'inspect_pcap_capture': '{}',
  'inspect_web_network_capture': '{}',
  'inspect_evidence_bundle': '{}',
  'inspect_analysis_view': '{"view":{"kind":"dart-aot","collection":"package_uris","offset":0,"limit":64}}',
};

const operationParameterHelp = <String, String>{
  'inspect_android_class': '需要精确 class_name。',
  'inspect_android_method': '需要 class_name 与 method_name；同名重载时额外提供 overload_index。',
  'trace_android_references': '需要 class_name，可选 method_name 与 overload_index。',
  'inspect_android_jni_bindings': 'query 可筛选 class_name、method_names、descriptors、abis、library_paths。',
  'inspect_dart_aot': '可选 abi，例如 arm64-v8a。',
  'search_bytes': '需要 pattern；可选 mask、start、end、cursor、limit。',
  'inspect_native_load_image': '读取 native load observations，不执行目标。',
  'binary_overview': '读取应用/二进制概览。',
  'inspect_managed_members': 'type_names 为完整类型名数组。',
  'extract_firmware': 'range 需要 offset 与 length；后端还应验证输出目录与预算。',
  'inspect_analysis_view': 'view 需要 kind、collection、offset、limit。',
};

class ReaBackend {
  ReaBackend(this.baseUrl, {this.token = ''});
  final String baseUrl;
  final String token;
  Map<String, String> get _headers => token.trim().isEmpty ? const {} : {'authorization': 'Bearer ${token.trim()}'};
  Uri _uri(String path, [Map<String, String>? query]) => Uri.parse('$baseUrl/${path.replaceFirst(RegExp(r'^/+'), '')}').replace(queryParameters: query);
  Future<Map<String, List<String>>> capabilities() async {
    final r = await http.get(_uri('/api/capabilities'), headers: _headers);
    _check(r);
    final data = jsonDecode(r.body);
    final result = <String, List<String>>{};
    for (final item in (data['families'] as List? ?? const [])) {
      if (item is Map) {
        final name = '${item['name'] ?? item['id'] ?? 'Unknown'}';
        final ops = [for (final op in (item['operations'] as List? ?? const [])) '$op'];
        result[name] = ops;
      }
    }
    return result;
  }
  Future<Map<String, dynamic>> mihomoStatus() async { final r = await http.get(_uri('/api/mihomo/status'), headers: _headers); _check(r); return jsonDecode(r.body) as Map<String, dynamic>; }
  Future<List<MihomoProxy>> mihomoProxies() async { final r = await http.get(_uri('/api/mihomo/proxies'), headers: _headers); _check(r); final data = jsonDecode(r.body) as Map; final proxies = (data['proxies'] as Map? ?? const {}); return [for (final x in proxies.values) if (x is Map) MihomoProxy.fromJson(Map<String, dynamic>.from(x))]; }
  Future<void> mihomoSelect(String group, String proxy) async { final r = await http.put(_uri('/api/mihomo/proxies/${Uri.encodeComponent(group)}'), headers: {..._headers, 'content-type': 'application/json'}, body: jsonEncode({'name': proxy})); _check(r); }
  Future<void> mihomoPatchConfig(Map<String, dynamic> config) async { final r = await http.patch(_uri('/api/mihomo/configs'), headers: {..._headers, 'content-type': 'application/json'}, body: jsonEncode(config)); _check(r); }
  Future<void> mihomoCloseConnections() async { final r = await http.delete(_uri('/api/mihomo/connections'), headers: _headers); _check(r); }
  Future<List<EvidenceRecord>> evidence() async {
    final r = await http.get(_uri('/api/evidence', {'limit': '50'}), headers: _headers);
    _check(r);
    final data = jsonDecode(r.body) as List;
    return data.map((x) => EvidenceRecord.fromJson(x as Map<String, dynamic>)).toList();
  }
  Future<AnalysisJob> submit(String operation, String target, Map<String, dynamic> parameters) async {
    final r = await http.post(_uri('/api/analyses'), headers: {..._headers, 'content-type': 'application/json'}, body: jsonEncode({'operation': operation, 'target': target, 'parameters': parameters}));
    _check(r);
    return AnalysisJob.fromJson(jsonDecode(r.body) as Map<String, dynamic>);
  }
  Future<AnalysisJob> job(String id) async {
    final r = await http.get(_uri('/api/analyses/$id'), headers: _headers);
    _check(r);
    return AnalysisJob.fromJson(jsonDecode(r.body) as Map<String, dynamic>);
  }
  static void _check(http.Response r) { if (r.statusCode < 200 || r.statusCode >= 300) throw Exception('Backend HTTP ${r.statusCode}: ${r.body}'); }
}

void main() => runApp(const ReaTvApp());

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
  static const _secureStorage = FlutterSecureStorage();
  final _backendCtrl = TextEditingController(text: 'http://192.0.2.2:8787');
  final _tokenCtrl = TextEditingController();
  final _targetCtrl = TextEditingController();
  final _parametersCtrl = TextEditingController(text: '{}');
  final _scopeFocus = FocusNode();
  final _targetFocus = FocusNode();
  List<String> families = [...defaultCapabilityFamilies];
  Map<String, List<String>> discoveredOperations = {};
  List<MihomoProxy> mihomoProxies = [];
  Map<String, dynamic>? mihomoStatus;
  Map<String, dynamic>? mihomoInstall;
  final _mihomoYamlCtrl = TextEditingController();
  String? mihomoMessage;
  List<EvidenceRecord> records = [];
  AnalysisJob? activeJob;
  Timer? _jobPoller;
  String selectedFamily = 'Android APK';
  String selectedOperation = 'inspect_android_package';
  String? error;
  bool loading = false;
  int tab = 0;

  @override void initState() { super.initState(); _loadBackend(); }
  @override void dispose() { _jobPoller?.cancel(); _backendCtrl.dispose(); _tokenCtrl.dispose(); _targetCtrl.dispose(); _parametersCtrl.dispose(); _mihomoYamlCtrl.dispose(); _scopeFocus.dispose(); _targetFocus.dispose(); super.dispose(); }
  Future<void> _loadBackend() async { final p = await SharedPreferences.getInstance(); final v = p.getString('rea_backend'); final token = await _secureStorage.read(key: 'rea_backend_token'); if (v != null) _backendCtrl.text = v; if (token != null) _tokenCtrl.text = token; }
  ReaBackend get _api => ReaBackend(_backendCtrl.text.trim(), token: _tokenCtrl.text);
  Future<void> _refreshMihomo() async { try { final status = await _api.mihomoStatus(); final proxies = await _api.mihomoProxies(); if (mounted) setState(() { mihomoStatus = status; mihomoProxies = proxies; }); } catch (e) { if (mounted) setState(() => error = '$e'); } }
  Future<void> _installMihomo() async { try { setState(() => mihomoMessage = '正在下载并验证官方 ARM64 二进制…'); final result = await _mihomoNative('downloadAndInstall', {'url': mihomoAssetUrl, 'sha256': mihomoAssetSha256}); if (mounted) setState(() { mihomoInstall = result; mihomoMessage = result['ok'] == true ? 'mihomo $mihomoVersion 已安装并通过 SHA-256 与版本校验。' : '安装未完成'; }); } catch (e) { if (mounted) setState(() => mihomoMessage = '安装失败：$e'); } }
  Future<void> _validateMihomoConfig({required bool activate}) async { try { setState(() => mihomoMessage = activate ? '正在校验并激活候选配置…' : '正在校验候选配置…'); final result = await _mihomoNative(activate ? 'activate' : 'validate', {'yaml': _mihomoYamlCtrl.text}); if (mounted) setState(() => mihomoMessage = '${result['ok'] == true ? '成功' : '失败'}${result['rolledBack'] == true ? '；已回滚至上一份配置' : ''}\n${result['output'] ?? ''}'); } catch (e) { if (mounted) setState(() => mihomoMessage = '配置操作失败：$e'); } }
  Future<void> _chooseMihomoNode(MihomoProxy group) async {
    final selected = await showDialog<String>(context: context, builder: (context) => AlertDialog(title: Text('切换 ${group.name}'), content: SizedBox(width: 680, child: ListView(children: [for (final node in group.all) ListTile(autofocus: node == group.now, title: Text(node), trailing: node == group.now ? const Icon(Icons.check, color: Color(0xff8dffe0)) : null, onTap: () => Navigator.pop(context, node))])), actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('取消'))]));
    if (selected == null || selected == group.now) return;
    try { await _api.mihomoSelect(group.name, selected); await _refreshMihomo(); } catch (e) { if (mounted) setState(() => error = '$e'); }
  }
  Future<void> _refresh() async {
    setState(() { loading = true; error = null; });
    try {
      final discovered = await _api.capabilities();
      discoveredOperations = discovered;
      families = discovered.isEmpty ? [...defaultCapabilityFamilies] : discovered.keys.toList();
      final ops = discoveredOperations[selectedFamily] ?? defaultOperationsByFamily[selectedFamily] ?? const <String>[];
      if (ops.isNotEmpty && !ops.contains(selectedOperation)) { selectedOperation = ops.first; _parametersCtrl.text = operationParameterTemplates[selectedOperation] ?? '{}'; }
      records = await _api.evidence();
    } catch (e) {
      error = '$e';
    }
    if (mounted) setState(() => loading = false);
  }
  void _watchJob(AnalysisJob job) {
    _jobPoller?.cancel();
    activeJob = job;
    if (job.status == 'completed' || job.status == 'failed') return;
    _jobPoller = Timer.periodic(const Duration(seconds: 2), (_) async {
      try {
        final latest = await _api.job(job.id);
        if (!mounted) return;
        setState(() => activeJob = latest);
        if (latest.status == 'completed' || latest.status == 'failed') {
          _jobPoller?.cancel();
          await _refresh();
        }
      } catch (e) {
        if (mounted) setState(() => error = '$e');
        _jobPoller?.cancel();
      }
    });
  }
  void _selectOperation(String? value) {
    final operation = value ?? selectedOperation;
    setState(() {
      selectedOperation = operation;
      _parametersCtrl.text = operationParameterTemplates[operation] ?? '{}';
    });
  }
  Map<String, dynamic> _parameters() {
    final decoded = jsonDecode(_parametersCtrl.text.trim().isEmpty ? '{}' : _parametersCtrl.text.trim());
    if (decoded is! Map<String, dynamic>) throw const FormatException('参数必须是 JSON 对象');
    return decoded;
  }
  Future<void> _saveBackend() async { final p = await SharedPreferences.getInstance(); await p.setString('rea_backend', _backendCtrl.text.trim()); await _secureStorage.write(key: 'rea_backend_token', value: _tokenCtrl.text); await _refresh(); }
  Future<void> _run() async { if (_targetCtrl.text.trim().isEmpty) { setState(() => error = '先输入目标路径或后端可见的目标标识。'); return; } setState(() { loading = true; error = null; }); try { final job = await _api.submit(selectedOperation, _targetCtrl.text.trim(), _parameters()); _watchJob(job); await _refresh(); } catch (e) { setState(() => error = '$e'); } finally { if (mounted) setState(() => loading = false); } }

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
            _NavButton(icon: Icons.router, label: 'mihomo 节点', selected: tab == 3, onTap: () { setState(() => tab = 3); _refreshMihomo(); }),
            const Spacer(),
            const Text('Evidence-first / read-only TV client', style: TextStyle(color: Color(0xff627080), fontSize: 12)),
          ],
        ),
      );
  Widget _page() { if (tab == 1) return _evidencePage(); if (tab == 2) return _settingsPage(); if (tab == 3) return _mihomoPage(); return _workspacePage(); }
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
                items: families.map((x) => DropdownMenuItem(value: x, child: Text(x, overflow: TextOverflow.ellipsis))).toList(),
                onChanged: (v) {
                  final family = v ?? selectedFamily;
                  final ops = discoveredOperations[family] ?? defaultOperationsByFamily[family] ?? const <String>[];
                  setState(() { selectedFamily = family; if (ops.isNotEmpty) { selectedOperation = ops.first; _parametersCtrl.text = operationParameterTemplates[selectedOperation] ?? '{}'; } });
                },
                decoration: const InputDecoration(labelText: '能力族', border: OutlineInputBorder()),
              ),
              const SizedBox(height: 14),
              DropdownButtonFormField<String>(
                isExpanded: true,
                initialValue: selectedOperation,
                items: ((discoveredOperations[selectedFamily] ?? defaultOperationsByFamily[selectedFamily] ?? const <String>[])).map((x) => DropdownMenuItem(value: x, child: Text(x, overflow: TextOverflow.ellipsis))).toList(),
                onChanged: _selectOperation,
                decoration: InputDecoration(labelText: '具体工具', helperText: operationParameterHelp[selectedOperation], border: const OutlineInputBorder()),
              ),
              const SizedBox(height: 14),
              TextField(
                controller: _parametersCtrl,
                maxLines: 3,
                decoration: const InputDecoration(
                  labelText: '工具参数 JSON',
                  hintText: '{"class_name":"com.example.MainActivity","abi":"arm64-v8a"}',
                  border: OutlineInputBorder(),
                ),
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
  Widget _statusPanel() => Card(child: Padding(padding: const EdgeInsets.all(22), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [const Text('状态', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700)), const SizedBox(height: 18), _Metric(label: '后端', value: _backendCtrl.text.isEmpty ? '未配置' : '已配置', color: const Color(0xff8dffe0)), _Metric(label: '能力族', value: '${families.length} 个'), _Metric(label: '证据记录', value: '${records.length} 条'), if (activeJob != null) _Metric(label: '当前任务', value: '${activeJob!.status} · ${activeJob!.operation}'), if (loading || activeJob?.status == 'queued' || activeJob?.status == 'running') const Padding(padding: EdgeInsets.only(top: 12), child: LinearProgressIndicator()), if (activeJob?.message != null) Padding(padding: const EdgeInsets.only(top: 10), child: Text(activeJob!.message!, style: const TextStyle(color: Color(0xff9ba8b7)))), if (error != null) Padding(padding: const EdgeInsets.only(top: 14), child: Text(error!, style: const TextStyle(color: Colors.orangeAccent))) ])));
  Future<void> _openEvidence(EvidenceRecord record) async {
    await showDialog<void>(
      context: context,
      builder: (_) => EvidenceDetailDialog(record: record),
    );
  }

  Widget _recentEvidence() => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('最近证据', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700)),
          const SizedBox(height: 12),
          Expanded(
            child: records.isEmpty
                ? const Center(child: Text('还没有证据。提交一次分析后，结果会保留在这里。', style: TextStyle(color: Color(0xff8d99a8))))
                : ListView.separated(
                    itemCount: records.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 10),
                    itemBuilder: (_, i) => _EvidenceTile(record: records[i], onTap: () => _openEvidence(records[i])),
                  ),
          ),
        ],
      );
  Widget _evidencePage() => Padding(padding: const EdgeInsets.all(36), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text('证据 ledger', style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w800)), const SizedBox(height: 8), const Text('每条结论都保留来源、置信度、权威级别和限制。', style: TextStyle(color: Color(0xff9ba8b7))), const SizedBox(height: 24), Expanded(child: _recentEvidence())]));
  Widget _mihomoPage() => Padding(
        padding: const EdgeInsets.all(36),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [Expanded(child: Text('mihomo 节点管理', style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w800))), IconButton(onPressed: _refreshMihomo, icon: const Icon(Icons.refresh))]),
          const SizedBox(height: 10),
          Wrap(spacing: 12, children: [FilledButton.icon(onPressed: _installMihomo, icon: const Icon(Icons.download), label: const Text('安装官方 v1.19.34')), OutlinedButton(onPressed: () => _validateMihomoConfig(activate: false), child: const Text('校验候选配置')), FilledButton(onPressed: () => _validateMihomoConfig(activate: true), child: const Text('激活并保留回滚点'))]),
          const SizedBox(height: 10),
          Text('仅应用内：TUN、VPN、系统代理和代理监听端口会被配置策略拒绝。', style: const TextStyle(color: Color(0xff9ba8b7))),
          if (mihomoInstall != null) Text('二进制：${mihomoInstall!['version'] ?? '已安装'}', style: const TextStyle(color: Color(0xff8dffe0))),
          if (mihomoMessage != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(mihomoMessage!, maxLines: 4, overflow: TextOverflow.ellipsis, style: const TextStyle(color: Color(0xffffd479)))),
          const SizedBox(height: 10),
          SizedBox(height: 140, child: TextField(controller: _mihomoYamlCtrl, expands: true, maxLines: null, minLines: null, decoration: const InputDecoration(labelText: '候选 mihomo YAML', hintText: '仅应用内配置；激活前会 mihomo -t 校验', border: OutlineInputBorder()))),
          const SizedBox(height: 14),
          Text(mihomoStatus == null ? '未连接 Controller' : 'Controller 已连接', style: TextStyle(color: mihomoStatus == null ? Colors.orangeAccent : const Color(0xff8dffe0))),
          if (mihomoStatus != null) Text('版本：${(mihomoStatus!['version'] as Map?)?['version'] ?? 'unknown'} · 模式：${(mihomoStatus!['configs'] as Map?)?['mode'] ?? 'unknown'}'),
          const SizedBox(height: 12),
          Expanded(child: mihomoProxies.isEmpty ? const Center(child: Text('没有节点数据，检查 mihomo Controller 地址和 Token。')) : ListView.separated(itemCount: mihomoProxies.length, separatorBuilder: (_, __) => const SizedBox(height: 8), itemBuilder: (_, i) { final p = mihomoProxies[i]; return Card(child: ListTile(leading: Icon(p.alive == false ? Icons.cloud_off : Icons.cloud_done, color: p.alive == false ? Colors.orangeAccent : const Color(0xff8dffe0)), title: Text(p.name), subtitle: Text('${p.type}${p.now == null ? '' : ' · 当前：${p.now}'}${p.delay == null ? '' : ' · ${p.delay} ms'}'), trailing: p.selectable ? FilledButton(onPressed: () => _chooseMihomoNode(p), child: const Text('切换')) : null)); })),
        ]),
      );
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
            SizedBox(
              width: 680,
              child: TextField(
                controller: _tokenCtrl,
                obscureText: true,
                decoration: const InputDecoration(labelText: 'Bearer Token（可选）', hintText: '仅发送到配置的 backend', border: OutlineInputBorder()),
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
  const _EvidenceTile({required this.record, this.onTap});
  final EvidenceRecord record;
  final VoidCallback? onTap;
  @override
  Widget build(BuildContext context) => Card(
        child: ListTile(
          onTap: onTap,
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

class EvidenceDetailDialog extends StatelessWidget {
  const EvidenceDetailDialog({required this.record, super.key});
  final EvidenceRecord record;
  @override
  Widget build(BuildContext context) => AlertDialog(
        title: Text(record.operation),
        content: SizedBox(
          width: 900,
          child: SingleChildScrollView(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('目标：${record.target}'),
              const SizedBox(height: 8),
              Text('Evidence ID：${record.id}', style: const TextStyle(color: Color(0xff9ba8b7))),
              Text('Confidence：${record.confidence}', style: const TextStyle(color: Color(0xffffd479))),
              Text('Authority：${record.authority}', style: const TextStyle(color: Color(0xff8dffe0))),
              if (record.location != null) Text('Location：${record.location}'),
              const SizedBox(height: 18),
              const Text('Limitations', style: TextStyle(fontWeight: FontWeight.w700)),
              ...record.limitations.map((x) => Padding(padding: const EdgeInsets.only(top: 4), child: Text('• $x'))),
              const SizedBox(height: 18),
              const Text('Normalized result', style: TextStyle(fontWeight: FontWeight.w700)),
              const SizedBox(height: 6),
              SelectableText(const JsonEncoder.withIndent('  ').convert(record.rawResult ?? {})),
            ]),
          ),
        ),
        actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('关闭'))],
      );
}


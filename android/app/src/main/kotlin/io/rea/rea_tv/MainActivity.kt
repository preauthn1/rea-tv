package io.rea.rea_tv

import android.os.Handler
import android.os.Looper
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.zip.GZIPInputStream

class MainActivity : FlutterActivity() {
    private val channelName = "io.rea.rea_tv/mihomo"
    private val worker = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName).setMethodCallHandler { call, result ->
            when (call.method) {
                "paths" -> result.success(paths())
                "downloadAndInstall" -> worker.execute { respond(result) { downloadAndInstall(call) } }
                "verify" -> worker.execute { respond(result) { verify(call) } }
                "validate" -> worker.execute { respond(result) { validate(call) } }
                "activate" -> worker.execute { respond(result) { activate(call) } }
                else -> result.notImplemented()
            }
        }
    }

    private fun respond(result: MethodChannel.Result, block: () -> Map<String, Any?>) {
        try { val value = block(); mainHandler.post { result.success(value) } }
        catch (e: Exception) { mainHandler.post { result.error("mihomo", e.message, null) } }
    }

    private fun root(): File = File(filesDir, "mihomo-v1.19.34").apply { mkdirs() }
    private fun binary(): File = File(root(), "bin/mihomo")
    private fun config(): File = File(root(), "active/config.yaml")
    private fun rollbackConfig(): File = File(root(), "rollback/config.yaml")
    private fun candidate(): File = File(root(), "candidate/config.yaml")
    private fun paths(): Map<String, Any?> = mapOf("root" to root().absolutePath, "binary" to binary().absolutePath, "config" to config().absolutePath)

    private fun safeName(value: String): String {
        require(value.matches(Regex("[A-Za-z0-9._-]{1,128}"))) { "invalid artifact name" }
        return value
    }
    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input -> val buffer = ByteArray(64 * 1024); while (true) { val read = input.read(buffer); if (read < 0) break; digest.update(buffer, 0, read) } }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
    private fun verify(call: MethodCall): Map<String, Any?> {
        val file = File(root(), "downloads/${safeName(call.argument<String>("name") ?: error("name required"))}")
        require(file.isFile) { "artifact not found" }
        val expected = expectedHash(call)
        val actual = sha256(file)
        return mapOf("ok" to (actual == expected), "sha256" to actual, "path" to file.absolutePath)
    }
    private fun expectedHash(call: MethodCall): String {
        val expected = (call.argument<String>("sha256") ?: error("sha256 required")).lowercase()
        require(expected.matches(Regex("[a-f0-9]{64}"))) { "invalid sha256" }
        return expected
    }
    private fun downloadAndInstall(call: MethodCall): Map<String, Any?> {
        val urlText = call.argument<String>("url") ?: error("url required")
        val uri = URL(urlText)
        require(uri.protocol == "https" && uri.host == "github.com" && uri.path == "/MetaCubeX/mihomo/releases/download/v1.19.34/mihomo-android-arm64-v8-v1.19.34.gz") { "unapproved mihomo artifact URL" }
        val expected = expectedHash(call)
        val archive = File(root(), "downloads/mihomo-android-arm64-v8-v1.19.34.gz").apply { parentFile?.mkdirs() }
        val partial = File(archive.parentFile, "${archive.name}.part")
        val connection = (uri.openConnection() as HttpURLConnection).apply { instanceFollowRedirects = true; connectTimeout = 30_000; readTimeout = 120_000; requestMethod = "GET" }
        try {
            require(connection.responseCode in 200..299) { "download HTTP ${connection.responseCode}" }
            connection.inputStream.use { input -> FileOutputStream(partial).use { output -> input.copyTo(output) } }
        } finally { connection.disconnect() }
        require(partial.renameTo(archive)) { "download finalization failed" }
        val actual = sha256(archive)
        require(actual == expected) { "artifact SHA-256 mismatch" }
        val destination = binary(); destination.parentFile?.mkdirs()
        val temp = File(destination.parentFile, "mihomo.new")
        GZIPInputStream(archive.inputStream()).use { input -> temp.outputStream().use { output -> input.copyTo(output) } }
        temp.setExecutable(true, true)
        val version = run(temp, listOf("-v"))
        require(version.exit == 0 && version.output.contains("v1.19.34")) { "unexpected mihomo version: ${version.output.take(300)}" }
        if (!temp.renameTo(destination)) { destination.delete(); require(temp.renameTo(destination)) { "atomic binary replacement failed" } }
        return mapOf("ok" to true, "sha256" to actual, "version" to version.output.trim(), "binary" to destination.absolutePath)
    }
    private data class RunResult(val exit: Int, val output: String)
    private fun run(executable: File, args: List<String>): RunResult {
        require(executable.isFile && executable.canExecute()) { "mihomo binary is not installed" }
        val process = ProcessBuilder(listOf(executable.absolutePath) + args).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        return RunResult(process.waitFor(), output)
    }
    private fun applicationOnlyPolicy(yaml: String) {
        val forbidden = listOf(
            Regex("(?m)^\\s*(?:port|socks-port|mixed-port|redir-port|tproxy-port)\\s*:\\s*(?!0(?:\\s*(?:#.*)?)?$).+"),
            Regex("(?m)^\\s*listeners\\s*:\\s*(?!\\[\\]\\s*(?:#.*)?$).+"),
            Regex("(?ms)^\\s*tun\\s*:\\s*.*?^\\s*enable\\s*:\\s*true\\b")
        )
        require(forbidden.none { it.containsMatchIn(yaml) }) { "application-only policy rejects proxy listeners or TUN" }
    }
    private fun readYaml(call: MethodCall): String {
        val yaml = call.argument<String>("yaml") ?: error("yaml required")
        require(yaml.length <= 1024 * 1024) { "config too large" }
        applicationOnlyPolicy(yaml)
        return yaml
    }
    private fun validate(call: MethodCall): Map<String, Any?> {
        val yaml = readYaml(call)
        candidate().parentFile?.mkdirs(); candidate().writeText(yaml)
        val result = run(binary(), listOf("-t", "-f", candidate().absolutePath))
        return mapOf("ok" to (result.exit == 0), "output" to result.output.take(8000), "candidate" to candidate().absolutePath)
    }
    private fun activate(call: MethodCall): Map<String, Any?> {
        val yaml = readYaml(call)
        candidate().parentFile?.mkdirs(); candidate().writeText(yaml)
        val checked = run(binary(), listOf("-t", "-f", candidate().absolutePath))
        if (checked.exit != 0) return mapOf("ok" to false, "rolledBack" to false, "output" to checked.output.take(8000))
        config().parentFile?.mkdirs()
        if (config().isFile) { rollbackConfig().parentFile?.mkdirs(); config().copyTo(rollbackConfig(), overwrite = true) }
        if (!candidate().renameTo(config())) { candidate().copyTo(config(), overwrite = true); candidate().delete() }
        val activeCheck = run(binary(), listOf("-t", "-f", config().absolutePath))
        if (activeCheck.exit == 0) return mapOf("ok" to true, "rolledBack" to false, "output" to activeCheck.output.take(8000), "config" to config().absolutePath)
        if (rollbackConfig().isFile) { rollbackConfig().copyTo(config(), overwrite = true); return mapOf("ok" to false, "rolledBack" to true, "output" to activeCheck.output.take(8000)) }
        return mapOf("ok" to false, "rolledBack" to false, "output" to activeCheck.output.take(8000))
    }

    override fun onDestroy() { worker.shutdown(); super.onDestroy() }
}

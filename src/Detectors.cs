using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32;

namespace EcomSentinel;

public interface IPollDetector
{
    string Name { get; }
    IEnumerable<Finding> Scan();
}

/// <summary>
/// Flags remote-access tools (every cycle, by name - cheap) and unsigned executables
/// running from temp folders (only for NEW processes, and the signature check runs only
/// for processes actually in a temp folder, cached by path - so steady state is cheap).
/// </summary>
public sealed class ProcessDetector : IPollDetector
{
    private readonly SentinelConfig _cfg;
    private readonly HashSet<int> _seen = new();
    private readonly Dictionary<string, bool> _sigCache = new(StringComparer.OrdinalIgnoreCase);
    public string Name => "procesos";

    /// <summary>PIDs of remote-access tools this cycle (used by the network detector).</summary>
    public HashSet<int> RemoteAccessPids { get; } = new();

    public ProcessDetector(SentinelConfig cfg) => _cfg = cfg;

    public IEnumerable<Finding> Scan()
    {
        RemoteAccessPids.Clear();
        var findings = new List<Finding>();
        var current = new HashSet<int>();

        foreach (var p in Process.GetProcesses())
        {
            try
            {
                int pid = p.Id;
                current.Add(pid);
                var name = p.ProcessName;
                var ln = name.ToLowerInvariant();

                if (Rules.IsSelf(ln)) continue; // nunca avisar del propio agente ni de su instalador
                bool whitelisted = _cfg.WhitelistProcessNames.Any(w => !string.IsNullOrEmpty(w) && ln.Contains(w.ToLowerInvariant()));
                if (whitelisted) continue;

                // Remote-access: cheap name check, every cycle.
                if (_cfg.RemoteAccessTools.Any(t => ln.Contains(t)))
                {
                    string rpath = SafePath(p);
                    var f = Rules.EvaluateProcess(name, rpath, true, _cfg);
                    if (f != null) findings.Add(f);
                    RemoteAccessPids.Add(pid);
                    continue;
                }

                // Unsigned-in-temp: only evaluate a process ONCE, and only read the signature
                // when the path is actually inside a temp folder (rare) - then cache it.
                if (_seen.Contains(pid)) continue;
                _seen.Add(pid);

                string path = SafePath(p);
                if (!string.IsNullOrEmpty(path) && Rules.IsInTemp(path, _cfg))
                {
                    bool signed = IsSignedCached(path);
                    var f = Rules.EvaluateProcess(name, path, signed, _cfg);
                    if (f != null) findings.Add(f);
                }
            }
            catch { }
            finally { p.Dispose(); }
        }

        _seen.IntersectWith(current); // forget dead PIDs (avoids unbounded growth / PID reuse)
        return findings;
    }

    private static string SafePath(Process p)
    {
        try { return p.MainModule?.FileName ?? ""; } catch { return ""; }
    }

    private bool IsSignedCached(string path)
    {
        if (_sigCache.TryGetValue(path, out var v)) return v;
        bool s = IsSigned(path);
        _sigCache[path] = s;
        return s;
    }

    private static bool IsSigned(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return true; // unknown -> don't flag
        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(path);
            return cert is not null;
        }
        catch { return false; }
    }
}

/// <summary>Snapshots autostart locations and alerts when a NEW one appears.</summary>
public sealed class PersistenceDetector : IPollDetector
{
    private HashSet<string>? _baseline;
    public string Name => "persistencia";

    public IEnumerable<Finding> Scan()
    {
        var current = Snapshot();
        if (_baseline == null)
        {
            _baseline = current;
            return Array.Empty<Finding>();
        }
        var findings = new List<Finding>();
        foreach (var e in current)
        {
            if (_baseline.Contains(e)) continue;
            var parts = e.Split('\u0001', 2);
            findings.Add(Rules.EvaluatePersistence(parts[0], parts.Length > 1 ? parts[1] : ""));
        }
        _baseline = current;
        return findings;
    }

    private static HashSet<string> Snapshot()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        AddRun(set, Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU");
        AddRun(set, Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU");
        AddRun(set, Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM");
        AddRun(set, Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM");
        AddRun(set, Registry.LocalMachine, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM32");

        foreach (var folder in new[] { Environment.SpecialFolder.Startup, Environment.SpecialFolder.CommonStartup })
        {
            try
            {
                var dir = Environment.GetFolderPath(folder);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                    foreach (var file in Directory.GetFiles(dir))
                        set.Add($"Inicio:{dir}\u0001{Path.GetFileName(file)}");
            }
            catch { }
        }
        return set;
    }

    private static void AddRun(HashSet<string> set, RegistryKey root, string sub, string label)
    {
        try
        {
            using var key = root.OpenSubKey(sub);
            if (key == null) return;
            foreach (var vn in key.GetValueNames())
            {
                var val = Convert.ToString(key.GetValue(vn)) ?? "";
                set.Add($"{label}\\{sub}:{vn}\u0001{val}");
            }
        }
        catch { }
    }
}

/// <summary>Reports outbound connections of remote-access tools only (secondary signal).</summary>
public sealed class NetworkDetector : IPollDetector
{
    private readonly ProcessDetector _proc;
    private readonly SentinelConfig _cfg;
    public string Name => "red";

    public NetworkDetector(ProcessDetector proc, SentinelConfig cfg)
    {
        _proc = proc;
        _cfg = cfg;
    }

    public IEnumerable<Finding> Scan()
    {
        if (_proc.RemoteAccessPids.Count == 0) return Array.Empty<Finding>();
        var findings = new List<Finding>();
        foreach (var c in Native.GetTcpConnections())
        {
            if (!_proc.RemoteAccessPids.Contains(c.Pid)) continue;
            if (!Rules.IsPublicIp(c.RemoteIp)) continue;
            string pname = "";
            try { using var p = Process.GetProcessById(c.Pid); pname = p.ProcessName; } catch { }
            var f = Rules.EvaluateNetwork(pname, c.Pid, c.RemoteIp, c.RemotePort, true, _cfg);
            if (f != null) findings.Add(f);
        }
        return findings;
    }
}

/// <summary>
/// STAR DETECTOR: watches %TEMP% and Downloads for a COPY of the browser credential store
/// (what an infostealer stages before exfiltration). Event-driven and cheap: it matches by
/// FILE NAME only (no file reads) unless DeepStagingScan is enabled. It does NOT watch the
/// real browser profile dirs, so the browser writing its own Cookies never triggers it.
/// </summary>
public sealed class CredentialStagingDetector
{
    private readonly SentinelConfig _cfg;
    private readonly List<FileSystemWatcher> _watchers = new();
    public string Name => "robo-credenciales";

    public CredentialStagingDetector(SentinelConfig cfg) => _cfg = cfg;

    public static IEnumerable<string> StagingDirs()
    {
        var dirs = new List<string>();
        foreach (var v in new[] { "TEMP", "TMP" })
        {
            var p = Environment.GetEnvironmentVariable(v);
            if (!string.IsNullOrEmpty(p)) dirs.Add(p);
        }
        try
        {
            dirs.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
        }
        catch { }
        return dirs.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    public void Start(Notifier notifier)
    {
        foreach (var dir in StagingDirs())
        {
            try
            {
                var w = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName,
                    InternalBufferSize = 64 * 1024,
                };
                // Let the OS filter: we only get notified for files NAMED like a credential
                // store, anywhere under temp. It never "reads" the rest - minimal overhead.
                foreach (var f in _cfg.CredentialFiles) w.Filters.Add(f);
                if (_cfg.DeepStagingScan) { w.Filters.Add("*.sqlite"); w.Filters.Add("*.db"); }
                w.Created += (_, e) => Handle(notifier, e.FullPath);
                w.Renamed += (_, e) => Handle(notifier, e.FullPath);
                w.Error += (_, _) => { }; // ignore buffer-overflow notifications
                w.EnableRaisingEvents = true;
                _watchers.Add(w);
            }
            catch { }
        }
    }

    public void Stop()
    {
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _watchers.Clear();
    }

    /// <summary>Exposed for --selftest. Cheap: name match only (content read only if DeepStagingScan).</summary>
    public Finding? Evaluate(string path)
    {
        var name = Path.GetFileName(path).ToLowerInvariant();
        bool nameMatch = _cfg.CredentialFiles.Any(f => name == f);
        if (!nameMatch)
        {
            if (!_cfg.DeepStagingScan) return null;
            if (!LooksLikeBrowserSqlite(path)) return null;
        }
        return new Finding
        {
            Severity = Severity.Critical,
            Category = "robo-credenciales",
            Title = "Posible copia de contrasenas/cookies del navegador en carpeta temporal",
            Detail = path,
            Explanation = "Ha aparecido en una carpeta temporal una copia del archivo donde el navegador guarda "
                        + "contrasenas/cookies. Es justo lo que hace un ladron de datos (infostealer) antes de "
                        + "enviarlas fuera. Si no reconoces un programa que lo haya hecho, cambia tus contrasenas "
                        + "desde otro equipo.",
            DedupKey = $"stage:{path.ToLowerInvariant()}",
        };
    }

    private void Handle(Notifier notifier, string path)
    {
        try
        {
            var f = Evaluate(path);
            if (f != null) notifier.Report(f);
        }
        catch { }
    }

    private static bool LooksLikeBrowserSqlite(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            var fi = new FileInfo(path);
            if (fi.Length < 512 || fi.Length > 50_000_000) return false;
            using var fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var hdr = new byte[16];
            if (fs.Read(hdr, 0, 16) < 16) return false;
            if (Encoding.ASCII.GetString(hdr, 0, 15) != "SQLite format 3") return false;
            fs.Seek(0, SeekOrigin.Begin);
            var buf = new byte[(int)Math.Min(fi.Length, 65536)];
            int read = fs.Read(buf, 0, buf.Length);
            var text = Encoding.ASCII.GetString(buf, 0, read).ToLowerInvariant();
            // Strong, browser-specific markers (generic apps do not use these) -> very few false positives.
            return text.Contains("encrypted_value") || text.Contains("moz_cookies") || text.Contains("moz_logins")
                   || text.Contains("action_url") || text.Contains("password_value") || text.Contains("card_number_encrypted");
        }
        catch { return false; }
    }
}

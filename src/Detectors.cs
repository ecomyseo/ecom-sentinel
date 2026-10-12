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

/// <summary>Flags remote-access tools and unsigned executables running from temp folders.</summary>
public sealed class ProcessDetector : IPollDetector
{
    private readonly SentinelConfig _cfg;
    public string Name => "procesos";
    public HashSet<int> SuspiciousPids { get; } = new();

    public ProcessDetector(SentinelConfig cfg) => _cfg = cfg;

    public IEnumerable<Finding> Scan()
    {
        SuspiciousPids.Clear();
        var findings = new List<Finding>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string name = p.ProcessName;
                string path = "";
                try { path = p.MainModule?.FileName ?? ""; } catch { /* protected process */ }
                bool signed = IsSigned(path);
                var f = Rules.EvaluateProcess(name, path, signed, _cfg);
                if (f != null)
                {
                    findings.Add(f);
                    SuspiciousPids.Add(p.Id);
                }
            }
            catch { /* process may have exited */ }
            finally { p.Dispose(); }
        }
        return findings;
    }

    private static bool IsSigned(string path)
    {
        // Unknown path -> treat as signed, so we never flag processes we simply cannot read.
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return true;
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

/// <summary>Reports outbound connections of processes already flagged as suspicious.</summary>
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
        if (_proc.SuspiciousPids.Count == 0) return Array.Empty<Finding>();
        var findings = new List<Finding>();
        foreach (var c in Native.GetTcpConnections())
        {
            if (!_proc.SuspiciousPids.Contains(c.Pid)) continue;
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
/// STAR DETECTOR: watches temp/Downloads/ProgramData for COPIES of the browser credential
/// store (what an infostealer stages before exfiltration). Event-driven (stays resident).
/// It deliberately does NOT watch the real browser profile dirs (%AppData%/%LocalAppData%),
/// so the browser writing its own Cookies never triggers it.
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
        foreach (var v in new[] { "TEMP", "TMP", "ProgramData", "PUBLIC" })
        {
            var p = Environment.GetEnvironmentVariable(v);
            if (!string.IsNullOrEmpty(p)) dirs.Add(p);
        }
        try
        {
            var dl = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            dirs.Add(dl);
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
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
                    EnableRaisingEvents = true,
                };
                w.Created += (_, e) => Handle(notifier, e.FullPath);
                w.Renamed += (_, e) => Handle(notifier, e.FullPath);
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

    /// <summary>Exposed for --selftest: returns a finding (or null) for a given path.</summary>
    public Finding? Evaluate(string path)
    {
        var name = Path.GetFileName(path).ToLowerInvariant();
        bool nameMatch = _cfg.CredentialFiles.Any(f => name == f);
        bool sqliteBrowser = !nameMatch && LooksLikeBrowserSqlite(path);
        if (!nameMatch && !sqliteBrowser) return null;
        return new Finding
        {
            Severity = Severity.Critical,
            Category = "credential-staging",
            Title = "Posible copia de credenciales/cookies del navegador en carpeta temporal",
            Detail = path,
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
            return text.Contains("cookies") || text.Contains("logins") || text.Contains("credit_cards")
                   || text.Contains("moz_cookies") || text.Contains("autofill");
        }
        catch { return false; }
    }
}

using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;
using EcomSentinel;

var mode = args.Length > 0 ? args[0].ToLowerInvariant().TrimStart('-') : "tray";

switch (mode)
{
    case "selftest":
        return SelfTest.Run();
    case "scan-once":
    case "scanonce":
        return RunScanOnce();
    case "run":
        return RunLoop();
    case "help":
    case "?":
        Console.WriteLine("Ecom Sentinel - uso: EcomSentinel [tray|run|scan-once|selftest]");
        Console.WriteLine("  (sin argumentos) -> icono en la barra del reloj (bandeja)");
        return 0;
    case "tray":
    default:
        return RunTray();
}

static (SentinelConfig cfg, Notifier notifier, ProcessDetector proc, List<IPollDetector> poll, CredentialStagingDetector staging) Build()
{
    var cfg = ConfigStore.Load();
    var notifier = new Notifier(cfg.Alerts, cfg.WhitelistPaths);
    var proc = new ProcessDetector(cfg);
    var poll = new List<IPollDetector> { proc, new PersistenceDetector(cfg), new NetworkDetector(proc, cfg) };
    var staging = new CredentialStagingDetector(cfg);
    return (cfg, notifier, proc, poll, staging);
}

static int RunTray()
{
    var (cfg, notifier, _, poll, staging) = Build();
    Application.EnableVisualStyles();
    Application.SetCompatibleTextRenderingDefault(false);
    Application.Run(new TrayApp(cfg, notifier, poll, staging));
    return 0;
}

static int RunScanOnce()
{
    var (cfg, notifier, _, poll, staging) = Build();
    Console.WriteLine($"Ecom Sentinel v0.2 - escaneo unico en {Environment.MachineName} ({DateTime.Now})");
    Console.WriteLine($"Carpetas de staging vigiladas: {string.Join(", ", CredentialStagingDetector.StagingDirs())}");
    Console.WriteLine($"Registro: {cfg.Alerts.LogFile}");
    int total = 0;
    foreach (var d in poll)
    {
        var findings = d.Scan().ToList();
        total += findings.Count;
        notifier.Report(findings);
    }
    Console.WriteLine(total == 0
        ? "Sin hallazgos en esta pasada (NO significa 'equipo limpio': ver README)."
        : $"{total} hallazgo(s).");
    return 0;
}

static int RunLoop()
{
    var (cfg, notifier, _, poll, staging) = Build();
    Console.WriteLine($"Ecom Sentinel v0.2 residente (consola) - {Environment.MachineName}. Ctrl+C para salir.");
    staging.Start(notifier);

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    try
    {
        while (!cts.IsCancellationRequested)
        {
            foreach (var d in poll)
            {
                try { notifier.Report(d.Scan()); }
                catch (Exception ex) { Console.Error.WriteLine($"[sentinel] detector {d.Name}: {ex.Message}"); }
            }
            try { Task.Delay(TimeSpan.FromSeconds(Math.Max(3, cfg.ScanIntervalSeconds)), cts.Token).Wait(cts.Token); }
            catch (OperationCanceledException) { }
        }
    }
    finally { staging.Stop(); }
    Console.WriteLine("Ecom Sentinel detenido.");
    return 0;
}

/// <summary>
/// Loads/saves the config from a WRITABLE location (%ProgramData%\EcomSentinel), because the
/// install dir (Program Files) is read-only for a non-elevated agent. Seeds it from the
/// installed default on first run. The log goes to the same writable folder.
/// </summary>
static class ConfigStore
{
    public static string Dir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EcomSentinel");
    public static string ConfigFile => Path.Combine(Dir, "appsettings.json");
    public static string LogFile => Path.Combine(Dir, "sentinel.log");

    private static JsonSerializerOptions Opts()
    {
        var o = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, WriteIndented = true };
        o.Converters.Add(new JsonStringEnumConverter());
        return o;
    }

    public static SentinelConfig Load()
    {
        try { Directory.CreateDirectory(Dir); } catch { }

        var appDefault = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        try
        {
            if (!File.Exists(ConfigFile) && File.Exists(appDefault)) File.Copy(appDefault, ConfigFile);
        }
        catch { }

        var cfg = new SentinelConfig();
        var src = File.Exists(ConfigFile) ? ConfigFile : (File.Exists(appDefault) ? appDefault : null);
        if (src != null)
        {
            try
            {
                var loaded = JsonSerializer.Deserialize<SentinelConfig>(File.ReadAllText(src), Opts());
                if (loaded != null) cfg = loaded;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[sentinel] config no valida, valores por defecto: {ex.Message}"); }
        }

        cfg.FillDefaults();
        cfg.Alerts.LogFile = LogFile; // always writable
        return cfg;
    }

    public static void Save(SentinelConfig cfg)
    {
        try
        {
            Directory.CreateDirectory(Dir);
            File.WriteAllText(ConfigFile, JsonSerializer.Serialize(cfg, Opts()));
        }
        catch { }
    }

    public static void AddWhitelistPath(SentinelConfig cfg, string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        var list = cfg.WhitelistPaths.ToList();
        if (!list.Contains(path, StringComparer.OrdinalIgnoreCase))
        {
            list.Add(path);
            cfg.WhitelistPaths = list.ToArray();
            Save(cfg);
        }
    }

    public static void AddWhitelistProcess(SentinelConfig cfg, string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        var n = name.ToLowerInvariant();
        var list = cfg.WhitelistProcessNames.ToList();
        if (!list.Contains(n, StringComparer.OrdinalIgnoreCase))
        {
            list.Add(n);
            cfg.WhitelistProcessNames = list.ToArray();
            Save(cfg);
        }
    }
}

/// <summary>Deterministic tests of the pure rules - no OS state, safe to run anywhere.</summary>
static class SelfTest
{
    public static int Run()
    {
        var cfg = new SentinelConfig();
        cfg.FillDefaults();
        var staging = new CredentialStagingDetector(cfg);
        int pass = 0, fail = 0;

        void Check(string name, bool ok)
        {
            Console.WriteLine($"  [{(ok ? "OK" : "FALLO")}] {name}");
            if (ok) pass++; else fail++;
        }

        var tmp = cfg.TempDirs.Length > 0 ? cfg.TempDirs[0] : Path.GetTempPath();

        Check("herramienta control remoto -> High",
            Rules.EvaluateProcess("AnyDesk", @"C:\Program Files\AnyDesk\AnyDesk.exe", true, cfg)?.Severity == Severity.High);
        Check("exe sin firma en temp -> High",
            Rules.EvaluateProcess("x", Path.Combine(tmp, "x.exe"), false, cfg)?.Severity == Severity.High);
        Check("exe firmado en temp -> no alerta",
            Rules.EvaluateProcess("x", Path.Combine(tmp, "x.exe"), true, cfg) == null);
        Check("proceso normal firmado -> no alerta",
            Rules.EvaluateProcess("notepad", @"C:\Windows\System32\notepad.exe", true, cfg) == null);
        Check("no avisa de si mismo (instalador) -> no alerta",
            Rules.EvaluateProcess("EcomSentinel-Setup-0.2.4", Path.Combine(tmp, "x.tmp"), false, cfg) == null);
        Check("acceso a credenciales por no-navegador -> Critical",
            Rules.EvaluateCredentialAccess("stealer", 1234, @"C:\x\Login Data", cfg)?.Severity == Severity.Critical);
        Check("navegador accede a lo suyo -> no alerta",
            Rules.EvaluateCredentialAccess("chrome", 1, @"C:\x\Cookies", cfg) == null);
        Check("staging: fichero llamado 'Cookies' -> Critical",
            staging.Evaluate(Path.Combine(tmp, "Cookies"))?.Severity == Severity.Critical);
        Check("staging: fichero normal -> no alerta",
            staging.Evaluate(Path.Combine(tmp, "documento.txt")) == null);
        Check("staging: perfil de navegador (Default/playwright) -> no alerta",
            staging.Evaluate(Path.Combine(tmp, "playwright_x", "Default", "Login Data")) == null);
        Check("staging: copia SUELTA 'Login Data' en temp -> Critical",
            staging.Evaluate(Path.Combine(tmp, "Login Data"))?.Severity == Severity.Critical);
        Check("red: control remoto saliente -> Medium",
            Rules.EvaluateNetwork("x", 1, "8.8.8.8", 443, true, cfg)?.Severity == Severity.Medium);
        Check("red: no vigilado -> no alerta",
            Rules.EvaluateNetwork("x", 1, "8.8.8.8", 443, false, cfg) == null);
        Check("IP publica", Rules.IsPublicIp("8.8.8.8"));
        Check("IP privada no es publica", !Rules.IsPublicIp("192.168.1.10"));
        Check("persistencia -> High",
            Rules.EvaluatePersistence("HKCU\\...\\Run:evil", @"C:\x\evil.exe").Severity == Severity.High);

        // Whitelist suppression
        var n = new Notifier(new AlertConfig { Console = false, LogFile = "", MinSeverity = Severity.Medium },
            new[] { "\\temp\\cookies" });
        int got = 0; n.OnAlert = _ => got++;
        n.Report(new Finding { Severity = Severity.Critical, Title = "x", Detail = @"C:\temp\Cookies", DedupKey = "a" });
        Check("lista blanca suprime el aviso", got == 0);

        Console.WriteLine($"\nResultado selftest: {pass} OK, {fail} FALLO(S).");
        return fail == 0 ? 0 : 1;
    }
}

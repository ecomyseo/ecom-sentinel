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
        return RunLoop();          // headless resident loop (servers / no desktop)
    case "help":
    case "?":
        Console.WriteLine("Ecom Sentinel - uso: EcomSentinel [tray|run|scan-once|selftest]");
        Console.WriteLine("  (sin argumentos) -> icono en la barra del reloj (bandeja)");
        return 0;
    case "tray":
    default:
        return RunTray();
}

static SentinelConfig LoadConfig()
{
    var cfg = new SentinelConfig();
    try
    {
        var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (File.Exists(path))
        {
            var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            opts.Converters.Add(new JsonStringEnumConverter());
            var loaded = JsonSerializer.Deserialize<SentinelConfig>(File.ReadAllText(path), opts);
            if (loaded != null) cfg = loaded;
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"[sentinel] appsettings.json no valido, uso valores por defecto: {ex.Message}");
    }
    cfg.FillDefaults();
    return cfg;
}

static (SentinelConfig cfg, Notifier notifier, ProcessDetector proc, List<IPollDetector> poll, CredentialStagingDetector staging) Build()
{
    var cfg = LoadConfig();
    var notifier = new Notifier(cfg.Alerts);
    var proc = new ProcessDetector(cfg);
    var poll = new List<IPollDetector> { proc, new PersistenceDetector(), new NetworkDetector(proc, cfg) };
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
        Check("acceso a credenciales por no-navegador -> Critical",
            Rules.EvaluateCredentialAccess("stealer", 1234, @"C:\x\Login Data", cfg)?.Severity == Severity.Critical);
        Check("navegador accede a lo suyo -> no alerta",
            Rules.EvaluateCredentialAccess("chrome", 1, @"C:\x\Cookies", cfg) == null);
        Check("staging: fichero llamado 'Cookies' -> Critical",
            staging.Evaluate(Path.Combine(tmp, "Cookies"))?.Severity == Severity.Critical);
        Check("staging: fichero normal -> no alerta",
            staging.Evaluate(Path.Combine(tmp, "documento.txt")) == null);
        Check("red: control remoto saliente -> Medium",
            Rules.EvaluateNetwork("x", 1, "8.8.8.8", 443, true, cfg)?.Severity == Severity.Medium);
        Check("red: no vigilado -> no alerta",
            Rules.EvaluateNetwork("x", 1, "8.8.8.8", 443, false, cfg) == null);
        Check("IP publica", Rules.IsPublicIp("8.8.8.8"));
        Check("IP privada no es publica", !Rules.IsPublicIp("192.168.1.10"));
        Check("persistencia -> High",
            Rules.EvaluatePersistence("HKCU\\...\\Run:evil", @"C:\x\evil.exe").Severity == Severity.High);

        Console.WriteLine($"\nResultado selftest: {pass} OK, {fail} FALLO(S).");
        return fail == 0 ? 0 : 1;
    }
}

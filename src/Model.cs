namespace EcomSentinel;

public enum Severity
{
    Info = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// <summary>A single detection result produced by a detector.</summary>
public sealed class Finding
{
    public DateTime TimeUtc { get; init; } = DateTime.UtcNow;
    public Severity Severity { get; init; }
    public string Category { get; init; } = "";
    public string Title { get; init; } = "";
    public string Detail { get; init; } = "";

    /// <summary>Plain-language explanation of why this matters (shown to the user).</summary>
    public string Explanation { get; init; } = "";

    /// <summary>Nombre de proceso (para la lista blanca por nombre), si aplica.</summary>
    public string ProcName { get; init; } = "";

    /// <summary>Stable key used to avoid sending the same alert over and over.</summary>
    public string DedupKey { get; init; } = "";

    public override string ToString()
        => $"[{TimeUtc:yyyy-MM-dd HH:mm:ss}Z] {Severity.ToString().ToUpperInvariant()} {Category}: {Title}"
           + (string.IsNullOrEmpty(Detail) ? "" : $" | {Detail}");
}

public sealed class SentinelConfig
{
    public int ScanIntervalSeconds { get; set; } = 20;

    /// <summary>Folders treated as "temporary" (filled from the environment when empty).</summary>
    public string[] TempDirs { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Read the first KB of each new temp file to spot a browser-DB copy by its contents.
    /// OFF by default: it is heavier (reads files). Name matching alone is cheap and enough.
    /// </summary>
    public bool DeepStagingScan { get; set; } = false;

    public string[] RemoteAccessTools { get; set; } =
    {
        "anydesk", "rustdesk", "teamviewer", "screenconnect", "connectwisecontrol",
        "atera", "splashtop", "supremo", "dwagent", "dwservice", "gotoassist",
        "remoteutilities", "ammyy", "ultraviewer", "chromeremotedesktop",
    };

    public string[] Browsers { get; set; } =
        { "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "edge" };

    /// <summary>Browser files that hold credentials / cookies (the infostealer target).</summary>
    public string[] CredentialFiles { get; set; } =
        { "login data", "cookies", "web data", "logins.json", "cookies.sqlite", "key4.db", "key3.db" };

    /// <summary>Process names never flagged (your own tools). Add dev/IDE tools here.</summary>
    public string[] WhitelistProcessNames { get; set; } =
        { "language_server_windows_x64", "ecomsentinel" };

    public string[] WhitelistHosts { get; set; } = Array.Empty<string>();

    /// <summary>Rutas/ficheros de confianza: si el aviso contiene uno, no se avisa. Lista blanca.</summary>
    public string[] WhitelistPaths { get; set; } = Array.Empty<string>();

    public AlertConfig Alerts { get; set; } = new();

    /// <summary>Que detectores estan activos. En una maquina de desarrollo conviene apagar
    /// UnsignedInTemp y Network (el "modo desarrollador"), que es el mayor ruido para un dev.</summary>
    public DetectConfig Detect { get; set; } = new();

    public void FillDefaults()
    {
        if (TempDirs.Length == 0)
        {
            var list = new List<string>();
            foreach (var v in new[] { "TEMP", "TMP", "APPDATA", "LOCALAPPDATA" })
            {
                var p = Environment.GetEnvironmentVariable(v);
                if (!string.IsNullOrEmpty(p)) list.Add(p);
            }
            var pd = Environment.GetEnvironmentVariable("ProgramData");
            if (!string.IsNullOrEmpty(pd)) list.Add(pd);
            TempDirs = list.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
    }
}

public sealed class AlertConfig
{
    public bool Console { get; set; } = true;
    public string LogFile { get; set; } = "sentinel.log";

    /// <summary>Only severities >= this are alerted. High by default to keep noise low.</summary>
    public Severity MinSeverity { get; set; } = Severity.High;

    public string WebhookUrl { get; set; } = "";
    public WhatsAppConfig WhatsApp { get; set; } = new();
    public SmtpConfig Smtp { get; set; } = new();
}

public sealed class WhatsAppConfig
{
    public string ApiUrl { get; set; } = "";
    public string ApiKey { get; set; } = "";
    public string To { get; set; } = "";
}

public sealed class SmtpConfig
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
    public string From { get; set; } = "";
    public string To { get; set; } = "";
    public bool UseSsl { get; set; } = true;
}

public sealed class DetectConfig
{
    public bool CredentialStaging { get; set; } = true; // robo de contrasenas/cookies (el nucleo)
    public bool RemoteAccess { get; set; } = true;      // AnyDesk/RustDesk/TeamViewer...
    public bool Persistence { get; set; } = true;       // nuevos arranques automaticos
    public bool UnsignedInTemp { get; set; } = true;    // ruidoso en maquinas de desarrollo
    public bool Network { get; set; } = true;           // conexiones de procesos vigilados
}

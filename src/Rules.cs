namespace EcomSentinel;

/// <summary>
/// Pure detection logic. No OS calls here so it can be unit-tested with synthetic
/// inputs (see <c>--selftest</c>). The collectors in Detectors.cs feed real data in.
/// </summary>
public static class Rules
{
    private static bool Whitelisted(string name, SentinelConfig cfg)
        => cfg.WhitelistProcessNames.Any(w => string.Equals(w, name, StringComparison.OrdinalIgnoreCase));

    public static bool IsInTemp(string path, SentinelConfig cfg)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.ToLowerInvariant();
        return cfg.TempDirs.Any(d => !string.IsNullOrEmpty(d) && p.StartsWith(d.ToLowerInvariant()));
    }

    public static Finding? EvaluateProcess(string name, string path, bool signed, SentinelConfig cfg)
    {
        var ln = (name ?? "").ToLowerInvariant();
        if (Whitelisted(ln, cfg)) return null;

        if (cfg.RemoteAccessTools.Any(t => ln.Contains(t)))
            return new Finding
            {
                Severity = Severity.High,
                Category = "remote-access",
                Title = $"Herramienta de control remoto en ejecucion: {name}",
                Detail = path,
                DedupKey = $"ra:{ln}:{path}",
            };

        if (!signed && IsInTemp(path, cfg))
            return new Finding
            {
                Severity = Severity.High,
                Category = "suspicious-process",
                Title = $"Ejecutable SIN FIRMA en carpeta temporal: {name}",
                Detail = path,
                DedupKey = $"unsigned:{path}",
            };

        return null;
    }

    /// <summary>The star rule: a non-browser process touching the browser's credential store.</summary>
    public static Finding? EvaluateCredentialAccess(string accessorName, int pid, string filePath, SentinelConfig cfg)
    {
        var ln = (accessorName ?? "").ToLowerInvariant();
        if (cfg.Browsers.Any(b => ln.Contains(b))) return null;      // browser reading its own data = normal
        if (Whitelisted(ln, cfg)) return null;

        return new Finding
        {
            Severity = Severity.Critical,
            Category = "credential-theft",
            Title = $"Proceso NO-navegador accede a credenciales del navegador: {accessorName} (PID {pid})",
            Detail = filePath,
            DedupKey = $"cred:{pid}:{filePath.ToLowerInvariant()}",
        };
    }

    public static bool LooksLikeCredentialFile(string filePath, SentinelConfig cfg)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        var p = filePath.ToLowerInvariant();
        // Must look like a browser profile path AND match a known credential file name.
        var looksBrowser = p.Contains("\\user data\\") || p.Contains("\\mozilla\\") || p.Contains("\\google\\")
                           || p.Contains("\\microsoft\\edge\\") || p.Contains("\\bravesoftware\\");
        if (!looksBrowser) return false;
        return cfg.CredentialFiles.Any(f => p.EndsWith("\\" + f) || p.EndsWith("/" + f));
    }

    /// <summary>Outbound connection from a process already flagged as suspicious.</summary>
    public static Finding? EvaluateNetwork(string procName, int pid, string remoteIp, int remotePort, bool suspiciousProcess, SentinelConfig cfg)
    {
        if (!suspiciousProcess) return null;
        if (cfg.WhitelistHosts.Any(h => h == remoteIp)) return null;
        return new Finding
        {
            Severity = Severity.High,
            Category = "network",
            Title = $"Proceso sospechoso con conexion saliente: {procName} -> {remoteIp}:{remotePort}",
            Detail = $"PID {pid}",
            DedupKey = $"net:{pid}:{remoteIp}:{remotePort}",
        };
    }

    public static Finding EvaluatePersistence(string location, string entry)
        => new()
        {
            Severity = Severity.High,
            Category = "persistence",
            Title = "Nuevo arranque automatico detectado",
            Detail = $"{location} => {entry}",
            DedupKey = $"persist:{location}:{entry}".ToLowerInvariant(),
        };

    public static bool IsPublicIp(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var addr)) return false;
        if (System.Net.IPAddress.IsLoopback(addr)) return false;
        var b = addr.GetAddressBytes();
        if (b.Length == 4)
        {
            if (b[0] == 10) return false;
            if (b[0] == 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 0) return false;
            return true;
        }
        // IPv6: treat link-local / unique-local / loopback as private.
        if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal) return false;
        if (b.Length == 16 && (b[0] & 0xfe) == 0xfc) return false; // fc00::/7
        return true;
    }
}

namespace EcomSentinel;

/// <summary>
/// Pure detection logic. No OS calls here so it can be unit-tested with synthetic
/// inputs (see <c>--selftest</c>). Each finding carries a plain-language explanation.
/// </summary>
public static class Rules
{
    private static bool Whitelisted(string name, SentinelConfig cfg)
        => cfg.WhitelistProcessNames.Any(w => !string.IsNullOrEmpty(w) && name.Contains(w.ToLowerInvariant()));

    /// <summary>El propio agente y su instalador nunca se marcan.</summary>
    public static bool IsSelf(string name)
        => (name ?? "").ToLowerInvariant().Contains("ecomsentinel");

    public static bool IsInTemp(string path, SentinelConfig cfg)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var p = path.ToLowerInvariant();
        return cfg.TempDirs.Any(d => !string.IsNullOrEmpty(d) && p.StartsWith(d.ToLowerInvariant()));
    }

    public static Finding? EvaluateProcess(string name, string path, bool signed, SentinelConfig cfg)
    {
        var ln = (name ?? "").ToLowerInvariant();
        if (IsSelf(ln)) return null;
        if (Whitelisted(ln, cfg)) return null;

        if (cfg.RemoteAccessTools.Any(t => ln.Contains(t)))
            return new Finding
            {
                Severity = Severity.High,
                Category = "control-remoto",
                Title = $"Programa de control remoto en ejecucion: {name}",
                Detail = string.IsNullOrEmpty(path) ? "(ruta no disponible)" : path,
                Explanation = "Un programa de control remoto permite manejar este equipo a distancia. "
                            + "Si no lo instalaste tu (o tu informatico), alguien podria estar entrando.",
                DedupKey = $"ra:{ln}:{path}",
            };

        if (!signed && IsInTemp(path, cfg))
            return new Finding
            {
                Severity = Severity.High,
                Category = "proceso-sospechoso",
                Title = $"Ejecutable SIN FIRMA en carpeta temporal: {name}",
                Detail = path,
                Explanation = "Un programa sin firma digital corriendo desde una carpeta temporal es tipico "
                            + "del malware; los programas legitimos suelen estar firmados y en 'Archivos de programa'.",
                DedupKey = $"unsigned:{path}",
            };

        return null;
    }

    /// <summary>A non-browser process touching the browser's credential store (live access).</summary>
    public static Finding? EvaluateCredentialAccess(string accessorName, int pid, string filePath, SentinelConfig cfg)
    {
        var ln = (accessorName ?? "").ToLowerInvariant();
        if (cfg.Browsers.Any(b => ln.Contains(b))) return null;
        if (Whitelisted(ln, cfg)) return null;

        return new Finding
        {
            Severity = Severity.Critical,
            Category = "robo-credenciales",
            Title = $"Un programa que NO es el navegador accede a tus contrasenas/cookies: {accessorName} (PID {pid})",
            Detail = filePath,
            Explanation = "Solo el navegador deberia abrir su archivo de contrasenas/cookies. "
                        + "Que otro programa lo lea es la senal clasica de un ladron de datos (infostealer).",
            DedupKey = $"cred:{pid}:{filePath.ToLowerInvariant()}",
        };
    }

    public static bool LooksLikeCredentialFile(string filePath, SentinelConfig cfg)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        var p = filePath.ToLowerInvariant();
        var looksBrowser = p.Contains("\\user data\\") || p.Contains("\\mozilla\\") || p.Contains("\\google\\")
                           || p.Contains("\\microsoft\\edge\\") || p.Contains("\\bravesoftware\\");
        if (!looksBrowser) return false;
        return cfg.CredentialFiles.Any(f => p.EndsWith("\\" + f) || p.EndsWith("/" + f));
    }

    /// <summary>Outbound connection from a REMOTE-ACCESS process. Secondary signal -> Medium.</summary>
    public static Finding? EvaluateNetwork(string procName, int pid, string remoteIp, int remotePort, bool watched, SentinelConfig cfg)
    {
        if (!watched) return null;
        if (cfg.WhitelistHosts.Any(h => h == remoteIp)) return null;
        return new Finding
        {
            Severity = Severity.Medium,
            Category = "red",
            Title = $"Programa de control remoto con conexion a Internet: {procName} -> {remoteIp}:{remotePort}",
            Detail = $"PID {pid} -> {remoteIp}:{remotePort}",
            Explanation = "Un programa de control remoto esta conectado a Internet; "
                        + "podria ser una sesion remota en curso. Confirmalo si no la iniciaste tu.",
            DedupKey = $"net:{pid}:{remoteIp}:{remotePort}",
        };
    }

    public static Finding EvaluatePersistence(string location, string entry)
        => new()
        {
            Severity = Severity.High,
            Category = "persistencia",
            Title = "Nuevo arranque automatico detectado",
            Detail = $"{location} => {entry}",
            Explanation = "Se ha anadido un programa que se ejecutara solo cada vez que enciendas el equipo. "
                        + "El malware lo usa para seguir activo aunque reinicies.",
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
        if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal) return false;
        if (b.Length == 16 && (b[0] & 0xfe) == 0xfc) return false;
        return true;
    }
}

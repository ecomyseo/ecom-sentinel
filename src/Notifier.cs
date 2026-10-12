using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;

namespace EcomSentinel;

/// <summary>Sends findings to the configured channels, once per finding (deduplicated).</summary>
public sealed class Notifier
{
    private readonly AlertConfig _cfg;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly string _host = Environment.MachineName;
    private readonly string _user = Environment.UserName;

    public Notifier(AlertConfig cfg) => _cfg = cfg;

    public void Report(IEnumerable<Finding> findings)
    {
        foreach (var f in findings) Report(f);
    }

    public void Report(Finding f)
    {
        if ((int)f.Severity < (int)_cfg.MinSeverity) return;

        lock (_lock)
        {
            if (!string.IsNullOrEmpty(f.DedupKey) && !_seen.Add(f.DedupKey)) return;
        }

        var line = $"{f} [host={_host} user={_user}]";

        if (_cfg.Console) WriteConsole(f, line);
        if (!string.IsNullOrEmpty(_cfg.LogFile)) TryLog(_cfg.LogFile, line);

        // Outbound channels: fire-and-forget, never crash the agent.
        if (!string.IsNullOrEmpty(_cfg.WebhookUrl)) _ = SafeAsync(() => SendWebhookAsync(f));
        var w = _cfg.WhatsApp;
        if (!string.IsNullOrEmpty(w.ApiUrl) && !string.IsNullOrEmpty(w.To)) _ = SafeAsync(() => SendWhatsAppAsync(f, line));
        if (!string.IsNullOrEmpty(_cfg.Smtp.Host) && !string.IsNullOrEmpty(_cfg.Smtp.To)) _ = SafeAsync(() => Task.Run(() => SendEmail(f, line)));
    }

    private static async Task SafeAsync(Func<Task> action)
    {
        try { await action().ConfigureAwait(false); }
        catch (Exception ex) { Console.Error.WriteLine($"[sentinel] alerta no enviada: {ex.Message}"); }
    }

    private static void WriteConsole(Finding f, string line)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = f.Severity switch
        {
            Severity.Critical => ConsoleColor.Red,
            Severity.High => ConsoleColor.Yellow,
            Severity.Medium => ConsoleColor.Cyan,
            _ => prev,
        };
        Console.WriteLine(line);
        Console.ForegroundColor = prev;
    }

    private static void TryLog(string path, string line)
    {
        try { File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8); }
        catch { /* disk/permission issues must not crash the agent */ }
    }

    private async Task SendWebhookAsync(Finding f)
    {
        var payload = JsonSerializer.Serialize(new
        {
            time = f.TimeUtc, severity = f.Severity.ToString(), category = f.Category,
            title = f.Title, detail = f.Detail, host = _host, user = _user,
        });
        using var content = new StringContent(payload, Encoding.UTF8, "application/json");
        using var resp = await Http.PostAsync(_cfg.WebhookUrl, content).ConfigureAwait(false);
    }

    private async Task SendWhatsAppAsync(Finding f, string line)
    {
        var w = _cfg.WhatsApp;
        var payload = JsonSerializer.Serialize(new { to = w.To, text = "🛡 Ecom Sentinel: " + line, @event = "alerta" });
        using var req = new HttpRequestMessage(HttpMethod.Post, w.ApiUrl)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        };
        if (!string.IsNullOrEmpty(w.ApiKey))
            req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + w.ApiKey);
        using var resp = await Http.SendAsync(req).ConfigureAwait(false);
    }

    private void SendEmail(Finding f, string line)
    {
        var s = _cfg.Smtp;
        using var msg = new MailMessage(s.From, s.To)
        {
            Subject = $"[Ecom Sentinel] {f.Severity}: {f.Title}",
            Body = line,
        };
        using var client = new SmtpClient(s.Host, s.Port) { EnableSsl = s.UseSsl };
        if (!string.IsNullOrEmpty(s.User))
            client.Credentials = new NetworkCredential(s.User, s.Password);
        client.Send(msg);
    }
}

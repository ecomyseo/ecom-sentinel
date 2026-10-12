using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace EcomSentinel;

/// <summary>
/// System-tray front-end: an icon next to the clock, a right-click menu and balloon
/// notifications. Reuses the same detection engine as the console modes.
/// </summary>
public sealed class TrayApp : ApplicationContext
{
    private readonly SentinelConfig _cfg;
    private readonly Notifier _notifier;
    private readonly List<IPollDetector> _poll;
    private readonly CredentialStagingDetector _staging;
    private readonly NotifyIcon _icon;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly Control _ui;
    private readonly ToolStripMenuItem _pauseItem;
    private static readonly Dictionary<Color, Icon> IconCache = new();
    private bool _paused;
    private int _alerts;

    public TrayApp(SentinelConfig cfg, Notifier notifier, List<IPollDetector> poll, CredentialStagingDetector staging)
    {
        _cfg = cfg;
        _notifier = notifier;
        _poll = poll;
        _staging = staging;

        _ui = new Control();
        _ = _ui.Handle; // force handle creation on the UI thread for cross-thread marshalling

        _icon = new NotifyIcon
        {
            Icon = MakeIcon(Color.SeaGreen),
            Visible = true,
            Text = "Ecom Sentinel - vigilancia activa",
        };

        var menu = new ContextMenuStrip();
        menu.Items.Add(new ToolStripMenuItem("Ecom Sentinel") { Enabled = false });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Escanear ahora", null, (_, _) => ScanNow()));
        _pauseItem = new ToolStripMenuItem("Pausar vigilancia", null, (_, _) => TogglePause());
        menu.Items.Add(_pauseItem);
        menu.Items.Add(new ToolStripMenuItem("Ver registro", null, (_, _) => OpenLog()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Salir", null, (_, _) => ExitApp()));
        _icon.ContextMenuStrip = menu;
        _icon.BalloonTipClicked += (_, _) => OpenLog();

        _notifier.OnAlert = ShowAlert;
        _staging.Start(_notifier);

        _timer = new System.Windows.Forms.Timer { Interval = Math.Max(3, cfg.ScanIntervalSeconds) * 1000 };
        _timer.Tick += (_, _) => { if (!_paused) RunPoll(); };
        _timer.Start();
        RunPoll();

        _icon.ShowBalloonTip(3000, "Ecom Sentinel", "Vigilancia activa en este equipo.", ToolTipIcon.Info);
    }

    private void RunPoll()
    {
        foreach (var d in _poll)
        {
            try { _notifier.Report(d.Scan()); } catch { }
        }
    }

    private void ScanNow()
    {
        RunPoll();
        _icon.ShowBalloonTip(2500, "Ecom Sentinel", "Escaneo manual completado.", ToolTipIcon.Info);
    }

    private void TogglePause()
    {
        _paused = !_paused;
        _pauseItem.Text = _paused ? "Reanudar vigilancia" : "Pausar vigilancia";
        _icon.Icon = MakeIcon(_paused ? Color.Gray : Color.SeaGreen);
        _icon.Text = _paused ? "Ecom Sentinel - EN PAUSA" : "Ecom Sentinel - vigilancia activa";
    }

    private void OpenLog()
    {
        try
        {
            if (string.IsNullOrEmpty(_cfg.Alerts.LogFile)) return;
            var path = Path.GetFullPath(_cfg.Alerts.LogFile);
            if (File.Exists(path))
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch { }
    }

    private void ShowAlert(Finding f)
    {
        try
        {
            if (!_ui.IsHandleCreated) return;
            _ui.BeginInvoke((Action)(() =>
            {
                _alerts++;
                _icon.Icon = MakeIcon(f.Severity >= Severity.High ? Color.Firebrick : Color.DarkOrange);
                _icon.Text = $"Ecom Sentinel - {_alerts} aviso(s)";
                var tipIcon = f.Severity >= Severity.High ? ToolTipIcon.Error : ToolTipIcon.Warning;
                _icon.ShowBalloonTip(7000, $"Ecom Sentinel: {f.Severity}", f.Title, tipIcon);
            }));
        }
        catch { }
    }

    private void ExitApp()
    {
        try
        {
            _timer.Stop();
            _staging.Stop();
            _icon.Visible = false;
            _icon.Dispose();
        }
        catch { }
        ExitThread();
    }

    private static Icon MakeIcon(Color color)
    {
        if (IconCache.TryGetValue(color, out var cached)) return cached;

        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            var shield = new[]
            {
                new Point(16, 2), new Point(29, 8), new Point(29, 17),
                new Point(16, 30), new Point(3, 17), new Point(3, 8),
            };
            using var brush = new SolidBrush(color);
            g.FillPolygon(brush, shield);
            using var pen = new Pen(Color.White, 2.4f);
            g.DrawLine(pen, 16, 9, 16, 22);  // vertical bar of a "+"
            g.DrawLine(pen, 9, 15, 23, 15);  // horizontal bar
        }
        var icon = Icon.FromHandle(bmp.GetHicon());
        IconCache[color] = icon;
        return icon;
    }
}

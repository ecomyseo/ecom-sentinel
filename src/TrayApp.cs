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
    private readonly ToolStripMenuItem _devItem;
    private static readonly Dictionary<Color, Icon> IconCache = new();
    private readonly List<Finding> _history = new();
    private bool _paused;
    private int _alerts;
    private Finding? _lastFinding;

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
        _devItem = new ToolStripMenuItem("Modo desarrollador (silenciar ruido)", null, (_, _) => ToggleDevMode())
        {
            Checked = !_cfg.Detect.UnsignedInTemp && !_cfg.Detect.Network,
        };
        menu.Items.Add(_devItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Marcar el ultimo aviso como seguro", null, (_, _) => MarkLastSafe()));
        menu.Items.Add(new ToolStripMenuItem("Panel de control (avisos, lista blanca, ajustes)", null, (_, _) => OpenDashboard()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Salir", null, (_, _) => ExitApp()));
        _icon.ContextMenuStrip = menu;
        _icon.BalloonTipClicked += (_, _) => OpenDashboard();

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

    private void MarkLastSafe()
    {
        var f = _lastFinding;
        if (f == null)
        {
            _icon.ShowBalloonTip(2500, "Ecom Sentinel", "No hay ningun aviso reciente que marcar.", ToolTipIcon.Info);
            return;
        }

        string what;
        if (!string.IsNullOrEmpty(f.ProcName))
        {
            // control-remoto / proceso-sospechoso: lista blanca por NOMBRE (anydesk, rustdesk...).
            ConfigStore.AddWhitelistProcess(_cfg, f.ProcName);
            what = "el programa '" + f.ProcName + "'";
        }
        else if (!string.IsNullOrEmpty(f.Detail))
        {
            ConfigStore.AddWhitelistPath(_cfg, f.Detail);
            _notifier.UpdateWhitelist(_cfg.WhitelistPaths);
            what = f.Detail;
        }
        else
        {
            _icon.ShowBalloonTip(2500, "Ecom Sentinel", "No hay nada que marcar en el ultimo aviso.", ToolTipIcon.Info);
            return;
        }

        _icon.ShowBalloonTip(6000, "Anadido a la lista blanca", "No se volvera a avisar de:\n" + what, ToolTipIcon.Info);
    }

    private void ToggleDevMode()
    {
        bool dev = !_devItem.Checked;
        _devItem.Checked = dev;
        _cfg.Detect.UnsignedInTemp = !dev;
        _cfg.Detect.Network = !dev;
        ConfigStore.Save(_cfg);
        _icon.ShowBalloonTip(7000, "Ecom Sentinel", dev
            ? "Modo desarrollador ON: no se avisa de ejecutables sin firma en temp ni de conexiones. Se mantiene el robo de credenciales, la persistencia y el control remoto."
            : "Modo normal (cliente): todos los detectores activos.", ToolTipIcon.Info);
    }

    private DashboardForm? _dash;

    private void OpenDashboard()
    {
        try
        {
            if (!_ui.IsHandleCreated) return;
            _ui.BeginInvoke((Action)(() =>
            {
                if (_dash != null && !_dash.IsDisposed) { _dash.Activate(); return; }
                _dash = new DashboardForm(_history.ToList(), _cfg, _notifier);
                _dash.FormClosed += (_, _) => _dash = null;
                _dash.Show();
            }));
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
                _lastFinding = f;
                _history.Add(f);
                if (_history.Count > 300) _history.RemoveRange(0, _history.Count - 300);
                _alerts++;
                _icon.Icon = MakeIcon(f.Severity >= Severity.High ? Color.Firebrick : Color.DarkOrange);
                _icon.Text = $"Ecom Sentinel - {_alerts} aviso(s)";
                var tipIcon = f.Severity >= Severity.High ? ToolTipIcon.Error : ToolTipIcon.Warning;
                // Path FIRST so it is always visible even if the balloon truncates the rest.
                var body = string.IsNullOrEmpty(f.Detail) ? "" : ("Donde: " + f.Detail + "\n\n");
                body += f.Explanation;
                body += "\n\n(Pulsa aqui para abrir el panel de control.)";
                _icon.ShowBalloonTip(20000, $"{f.Severity}: {f.Title}", body, tipIcon);
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
            g.DrawLine(pen, 16, 9, 16, 22);
            g.DrawLine(pen, 9, 15, 23, 15);
        }
        var icon = Icon.FromHandle(bmp.GetHicon());
        IconCache[color] = icon;
        return icon;
    }
}

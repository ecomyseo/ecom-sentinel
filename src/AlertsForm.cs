using System.Windows.Forms;

namespace EcomSentinel;

/// <summary>
/// Panel de control propio (no un fichero de texto): pestanas Avisos, Lista blanca,
/// Registro y Ajustes. Permite anadir a la lista blanca por fichero/programa o carpeta,
/// quitar entradas, ver el registro en pantalla y cambiar los ajustes.
/// </summary>
public sealed class DashboardForm : Form
{
    private readonly SentinelConfig _cfg;
    private readonly Notifier _notifier;
    private readonly List<Finding> _findings;

    private ListView _lvAlerts = null!;
    private ListView _lvWhite = null!;
    private TextBox _txtLog = null!;

    public DashboardForm(List<Finding> findings, SentinelConfig cfg, Notifier notifier)
    {
        _cfg = cfg;
        _notifier = notifier;
        _findings = findings;

        Text = "Ecom Sentinel - Panel de control";
        Width = 980;
        Height = 600;
        StartPosition = FormStartPosition.CenterScreen;

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(BuildAlertsTab());
        tabs.TabPages.Add(BuildWhitelistTab());
        tabs.TabPages.Add(BuildLogTab());
        tabs.TabPages.Add(BuildSettingsTab());
        Controls.Add(tabs);
    }

    // ---------------- helpers ----------------

    private static Button Btn(string text, EventHandler onClick)
    {
        var b = new Button { Text = text, AutoSize = true, Margin = new Padding(4, 2, 4, 2) };
        b.Click += onClick;
        return b;
    }

    private void Apply()
    {
        _notifier.UpdateWhitelist(_cfg.WhitelistPaths);
        ConfigStore.Save(_cfg);
    }

    private static string? Prompt(IWin32Window owner, string title, string label)
    {
        using var f = new Form
        {
            Text = title, Width = 460, Height = 160, StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog, MinimizeBox = false, MaximizeBox = false,
        };
        var lbl = new Label { Text = label, Left = 12, Top = 14, Width = 420 };
        var tb = new TextBox { Left = 14, Top = 42, Width = 420 };
        var ok = new Button { Text = "Aceptar", Left = 260, Top = 78, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Cancelar", Left = 350, Top = 78, DialogResult = DialogResult.Cancel };
        f.Controls.AddRange(new Control[] { lbl, tb, ok, cancel });
        f.AcceptButton = ok;
        f.CancelButton = cancel;
        return f.ShowDialog(owner) == DialogResult.OK && tb.Text.Trim().Length > 0 ? tb.Text.Trim() : null;
    }

    // ---------------- tab: Avisos ----------------

    private TabPage BuildAlertsTab()
    {
        var page = new TabPage("Avisos");
        _lvAlerts = new ListView
        {
            Dock = DockStyle.Fill, View = View.Details, CheckBoxes = true, FullRowSelect = true, GridLines = true,
        };
        _lvAlerts.Columns.Add("Hora", 110);
        _lvAlerts.Columns.Add("Gravedad", 75);
        _lvAlerts.Columns.Add("Tipo", 150);
        _lvAlerts.Columns.Add("Que", 300);
        _lvAlerts.Columns.Add("Ubicacion / programa", 300);

        foreach (var f in Enumerable.Reverse(_findings))
        {
            var key = string.IsNullOrEmpty(f.ProcName) ? f.Detail : f.ProcName;
            _lvAlerts.Items.Add(new ListViewItem(new[]
            {
                f.TimeUtc.ToLocalTime().ToString("HH:mm:ss"), f.Severity.ToString(), f.Category, f.Title, key,
            })
            { Tag = f });
        }

        var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, WrapContents = false, Padding = new Padding(6) };
        bar.Controls.Add(Btn("Seleccionar todo", (_, _) => SetAll(_lvAlerts, true)));
        bar.Controls.Add(Btn("Ninguno", (_, _) => SetAll(_lvAlerts, false)));
        bar.Controls.Add(Btn("Anadir a lista blanca (fichero / programa)", (_, _) => AddCheckedAlerts(false)));
        bar.Controls.Add(Btn("Anadir CARPETA entera a lista blanca", (_, _) => AddCheckedAlerts(true)));

        page.Controls.Add(_lvAlerts);
        page.Controls.Add(bar);
        return page;
    }

    private static void SetAll(ListView lv, bool value)
    {
        foreach (ListViewItem i in lv.Items) i.Checked = value;
    }

    private void AddCheckedAlerts(bool folder)
    {
        var done = new List<ListViewItem>();
        foreach (ListViewItem it in _lvAlerts.Items)
        {
            if (!it.Checked) continue;
            var f = (Finding)it.Tag!;
            if (!string.IsNullOrEmpty(f.ProcName))
                ConfigStore.AddWhitelistProcess(_cfg, f.ProcName);
            else if (!string.IsNullOrEmpty(f.Detail))
                ConfigStore.AddWhitelistPath(_cfg, folder ? (Path.GetDirectoryName(f.Detail) ?? f.Detail) : f.Detail);
            else continue;
            done.Add(it);
        }
        if (done.Count == 0) { MessageBox.Show(this, "Marca al menos un aviso con su casilla.", "Ecom Sentinel"); return; }
        Apply();
        foreach (var it in done) _lvAlerts.Items.Remove(it);
        RefreshWhitelist();
        MessageBox.Show(this, done.Count + " anadido(s) a la lista blanca" + (folder ? " (carpeta entera)." : "."), "Ecom Sentinel");
    }

    // ---------------- tab: Lista blanca ----------------

    private TabPage BuildWhitelistTab()
    {
        var page = new TabPage("Lista blanca");
        _lvWhite = new ListView
        {
            Dock = DockStyle.Fill, View = View.Details, CheckBoxes = true, FullRowSelect = true, GridLines = true,
        };
        _lvWhite.Columns.Add("Tipo", 110);
        _lvWhite.Columns.Add("Valor (no se avisara de esto)", 760);
        RefreshWhitelist();

        var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, WrapContents = false, Padding = new Padding(6) };
        bar.Controls.Add(Btn("Quitar seleccionados", (_, _) => RemoveCheckedWhite()));
        bar.Controls.Add(Btn("Anadir carpeta...", (_, _) => AddFolder()));
        bar.Controls.Add(Btn("Anadir fichero...", (_, _) => AddFile()));
        bar.Controls.Add(Btn("Anadir programa...", (_, _) => AddProgram()));

        page.Controls.Add(_lvWhite);
        page.Controls.Add(bar);
        return page;
    }

    private void RefreshWhitelist()
    {
        if (_lvWhite == null) return;
        _lvWhite.Items.Clear();
        foreach (var p in _cfg.WhitelistProcessNames)
            _lvWhite.Items.Add(new ListViewItem(new[] { "Programa", p }) { Tag = ("proc", p) });
        foreach (var p in _cfg.WhitelistPaths)
            _lvWhite.Items.Add(new ListViewItem(new[] { "Ruta/Carpeta", p }) { Tag = ("path", p) });
    }

    private void RemoveCheckedWhite()
    {
        int n = 0;
        foreach (ListViewItem it in _lvWhite.Items)
        {
            if (!it.Checked) continue;
            var (kind, val) = ((string, string))it.Tag!;
            if (kind == "proc") ConfigStore.RemoveWhitelistProcess(_cfg, val);
            else ConfigStore.RemoveWhitelistPath(_cfg, val);
            n++;
        }
        if (n == 0) { MessageBox.Show(this, "Marca al menos una entrada.", "Ecom Sentinel"); return; }
        Apply();
        RefreshWhitelist();
    }

    private void AddFolder()
    {
        using var dlg = new FolderBrowserDialog { Description = "Carpeta de confianza (no se avisara de nada dentro)" };
        if (dlg.ShowDialog(this) == DialogResult.OK && !string.IsNullOrWhiteSpace(dlg.SelectedPath))
        {
            ConfigStore.AddWhitelistPath(_cfg, dlg.SelectedPath);
            Apply(); RefreshWhitelist();
        }
    }

    private void AddFile()
    {
        using var dlg = new OpenFileDialog { Title = "Fichero de confianza" };
        if (dlg.ShowDialog(this) == DialogResult.OK && !string.IsNullOrWhiteSpace(dlg.FileName))
        {
            ConfigStore.AddWhitelistPath(_cfg, dlg.FileName);
            Apply(); RefreshWhitelist();
        }
    }

    private void AddProgram()
    {
        var name = Prompt(this, "Anadir programa", "Nombre del programa (p. ej. anydesk, rustdesk):");
        if (!string.IsNullOrWhiteSpace(name))
        {
            ConfigStore.AddWhitelistProcess(_cfg, name);
            Apply(); RefreshWhitelist();
        }
    }

    // ---------------- tab: Registro ----------------

    private TabPage BuildLogTab()
    {
        var page = new TabPage("Registro");
        _txtLog = new TextBox
        {
            Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false,
            Font = new System.Drawing.Font("Consolas", 9f),
        };
        var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, WrapContents = false, Padding = new Padding(6) };
        bar.Controls.Add(Btn("Refrescar", (_, _) => LoadLog()));
        bar.Controls.Add(Btn("Vaciar registro", (_, _) => ClearLog()));
        page.Controls.Add(_txtLog);
        page.Controls.Add(bar);
        LoadLog();
        return page;
    }

    private void LoadLog()
    {
        try
        {
            var path = _cfg.Alerts.LogFile;
            _txtLog.Text = !string.IsNullOrEmpty(path) && File.Exists(path)
                ? string.Join(Environment.NewLine, File.ReadLines(path).Reverse().Take(500))
                : "(sin registro todavia)";
        }
        catch (Exception ex) { _txtLog.Text = "No se pudo leer el registro: " + ex.Message; }
    }

    private void ClearLog()
    {
        try
        {
            var path = _cfg.Alerts.LogFile;
            if (!string.IsNullOrEmpty(path) && File.Exists(path)) File.WriteAllText(path, "");
            LoadLog();
        }
        catch { }
    }

    // ---------------- tab: Ajustes ----------------

    private TabPage BuildSettingsTab()
    {
        var page = new TabPage("Ajustes");
        var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(14), AutoScroll = true };

        panel.Controls.Add(new Label { Text = "Que vigilar:", AutoSize = true, Font = new System.Drawing.Font(Font, System.Drawing.FontStyle.Bold), Margin = new Padding(0, 4, 0, 4) });
        var chkCred = Chk("Robo de contrasenas/cookies (recomendado)", _cfg.Detect.CredentialStaging);
        var chkRa = Chk("Programas de control remoto", _cfg.Detect.RemoteAccess);
        var chkPer = Chk("Nuevos arranques automaticos (persistencia)", _cfg.Detect.Persistence);
        var chkUns = Chk("Ejecutables sin firma en temp (ruidoso en PC de desarrollo)", _cfg.Detect.UnsignedInTemp);
        var chkNet = Chk("Conexiones de red de procesos vigilados", _cfg.Detect.Network);
        foreach (var c in new[] { chkCred, chkRa, chkPer, chkUns, chkNet }) panel.Controls.Add(c);

        var bDev = Btn("Activar MODO DESARROLLADOR (apaga sin-firma-en-temp y red)", (_, _) =>
        {
            chkUns.Checked = false; chkNet.Checked = false;
        });
        panel.Controls.Add(bDev);

        panel.Controls.Add(new Label { Text = "Nivel minimo para avisar:", AutoSize = true, Margin = new Padding(0, 10, 0, 2) });
        var cmbSev = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
        cmbSev.Items.AddRange(new object[] { "Medium", "High", "Critical" });
        cmbSev.SelectedItem = _cfg.Alerts.MinSeverity.ToString();
        panel.Controls.Add(cmbSev);

        panel.Controls.Add(new Label { Text = "Avisos por WhatsApp (opcional):", AutoSize = true, Font = new System.Drawing.Font(Font, System.Drawing.FontStyle.Bold), Margin = new Padding(0, 14, 0, 4) });
        var txtWaUrl = LabeledBox(panel, "URL de la API (mensajero):", _cfg.Alerts.WhatsApp.ApiUrl);
        var txtWaKey = LabeledBox(panel, "Clave (Bearer):", _cfg.Alerts.WhatsApp.ApiKey);
        var txtWaTo = LabeledBox(panel, "Numero destino (34...):", _cfg.Alerts.WhatsApp.To);

        var bSave = Btn("GUARDAR AJUSTES", (_, _) =>
        {
            _cfg.Detect.CredentialStaging = chkCred.Checked;
            _cfg.Detect.RemoteAccess = chkRa.Checked;
            _cfg.Detect.Persistence = chkPer.Checked;
            _cfg.Detect.UnsignedInTemp = chkUns.Checked;
            _cfg.Detect.Network = chkNet.Checked;
            if (Enum.TryParse<Severity>((string)(cmbSev.SelectedItem ?? "High"), out var sev)) _cfg.Alerts.MinSeverity = sev;
            _cfg.Alerts.WhatsApp.ApiUrl = txtWaUrl.Text.Trim();
            _cfg.Alerts.WhatsApp.ApiKey = txtWaKey.Text.Trim();
            _cfg.Alerts.WhatsApp.To = txtWaTo.Text.Trim();
            Apply();
            MessageBox.Show(this, "Ajustes guardados. Se aplican al momento (algunos tras el proximo escaneo).", "Ecom Sentinel");
        });
        bSave.Margin = new Padding(0, 14, 0, 0);
        panel.Controls.Add(bSave);

        page.Controls.Add(panel);
        return page;
    }

    private CheckBox Chk(string text, bool value) => new() { Text = text, Checked = value, AutoSize = true, Margin = new Padding(0, 2, 0, 2) };

    private TextBox LabeledBox(FlowLayoutPanel panel, string label, string value)
    {
        panel.Controls.Add(new Label { Text = label, AutoSize = true, Margin = new Padding(0, 6, 0, 0) });
        var tb = new TextBox { Text = value, Width = 500 };
        panel.Controls.Add(tb);
        return tb;
    }
}

using System.Collections.ObjectModel;
using AI.CyberDefense.Desktop.Models;

namespace AI.CyberDefense.Desktop.ViewModels;

public sealed class MainWindowViewModel : ViewModelBase
{
    private NavigationItem _selectedNavigationItem;

    public MainWindowViewModel()
    {
        NavigationItems = new ObservableCollection<NavigationItem>
        {
            new("Dashboard", "Squares2X2"),
            new("Upload Logs", "Upload"),
            new("Threat Analysis", "Shield"),
            new("Incidents", "Alert"),
            new("Reports", "Document"),
            new("Settings", "Gear"),
            new("About", "Info")
        };

        _selectedNavigationItem = NavigationItems[0];

        Metrics = new ObservableCollection<DashboardMetric>
        {
            new("Total Logs", "18,420", "+12% today", "AccentBrush"),
            new("Threats Detected", "37", "8 require review", "HighBrush"),
            new("Critical Incidents", "3", "active containment", "CriticalBrush"),
            new("High Incidents", "9", "triage queue", "HighBrush"),
            new("Medium", "16", "watchlist", "MediumBrush"),
            new("Low", "41", "auto-enriched", "LowBrush")
        };

        RecentAlerts = new ObservableCollection<AlertItem>
        {
            new("09:42", "Critical", "Repeated privilege escalation attempts", "WIN-DC-01", "MITRE T1068 | NIST Detect", 94),
            new("09:31", "High", "Suspicious SSH brute force pattern", "linux-auth-02", "MITRE T1110 | NIST Respond", 89),
            new("09:08", "Medium", "Unexpected web shell indicators in access logs", "nginx-edge-01", "MITRE T1505.003 | NIST Detect", 76),
            new("08:56", "Low", "Unusual service restart sequence", "api-node-03", "MITRE T1569 | NIST Identify", 61)
        };
    }

    public ObservableCollection<NavigationItem> NavigationItems { get; }

    public ObservableCollection<DashboardMetric> Metrics { get; }

    public ObservableCollection<AlertItem> RecentAlerts { get; }

    public NavigationItem SelectedNavigationItem
    {
        get => _selectedNavigationItem;
        set
        {
            if (SetProperty(ref _selectedNavigationItem, value))
            {
                OnPropertyChanged(nameof(CurrentViewTitle));
                OnPropertyChanged(nameof(CurrentViewSubtitle));
            }
        }
    }

    public string CurrentViewTitle => SelectedNavigationItem.Label;

    public string CurrentViewSubtitle => SelectedNavigationItem.Label switch
    {
        "Dashboard" => "Live SOC overview across uploaded logs, incidents, severity, and framework mappings.",
        "Upload Logs" => "Upload EVTX, auth.log, syslog, web server, JSON, or plain text logs for analysis.",
        "Threat Analysis" => "Review AI findings with severity, confidence, affected assets, and ATT&CK context.",
        "Incidents" => "Track analyst-ready incidents from detection through response and recovery.",
        "Reports" => "Generate incident PDFs with timelines, recommendations, and compliance mappings.",
        "Settings" => "Configure OpenAI, local database storage, log folders, and application preferences.",
        _ => "AI Cyber Defense Network MVP desktop console."
    };
}

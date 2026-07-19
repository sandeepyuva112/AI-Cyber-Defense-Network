namespace AI.CyberDefense.Desktop.Models;

public sealed record DashboardMetric(
    string Title,
    string Value,
    string Trend,
    string AccentResourceKey);

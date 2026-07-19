namespace AI.CyberDefense.Desktop.Models;

public sealed record AlertItem(
    string Time,
    string Severity,
    string Title,
    string Asset,
    string FrameworkMapping,
    int Confidence);

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.IO;
using System.Text.Json;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("🔍 WebRecon Enterprise v3.0 - Production");
        
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: dotnet run https://scanme.nmap.org");
            return;
        }

        var target = NormalizeTarget(args[0]);
        if (string.IsNullOrEmpty(target))
        {
            Console.WriteLine("❌ Invalid target");
            return;
        }

        Console.WriteLine($"Target: {target}");
        Directory.CreateDirectory("reports");

        var recon = new WebRecon(target);
        var result = await recon.ScanAsync();
        await recon.GenerateReportsAsync(result);

        Console.WriteLine($"✅ Complete | {result.Risk.Level} ({result.Risk.Score}/100)");
        Console.WriteLine("📁 reports/report.json | report.html");
    }

    private static string NormalizeTarget(string input)
    {
        input = input.Trim().TrimEnd('/');
        
        if (!input.StartsWith("http://") && !input.StartsWith("https://"))
            input = "https://" + input;

        try
        {
            var uri = new Uri(input);
            return uri.ToString();
        }
        catch
        {
            return null;
        }
    }
}

public class WebRecon : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _httpSemaphore;
    private readonly SemaphoreSlim _portSemaphore;
    private bool _disposed;

    public WebRecon(string target)
    {
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(12) };
        _httpSemaphore = new SemaphoreSlim(5, 5);  // HTTP rate limit
        _portSemaphore = new SemaphoreSlim(50, 50); // Port scan concurrency
    }

    public async Task<ScanResult> ScanAsync()
    {
        var result = new ScanResult { Target = _httpClient.BaseAddress?.ToString() ?? "" };

        // SEPARATE SEMAPHORES - NO CONTENTION
        var tasks = new[]
        {
            ScanHeadersAsync(result),
            ScanPortsAsync(result),
            ScanDirectoriesAsync(result),
            ScanTechnologiesAsync(result)
        };

        await Task.WhenAll(tasks);
        result.Risk = RiskCalculator.Calculate(result);  // STATIC - NO STATE CONFUSION
        return result;
    }

    private async Task ScanHeadersAsync(ScanResult result)
    {
        try
        {
            await _httpSemaphore.WaitAsync();
            using var req = new HttpRequestMessage(HttpMethod.Head, result.Target);
            using var resp = await _httpClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);
            
            result.Headers = resp.Headers
                .ToDictionary(h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Headers: {ex.Message}");
        }
        finally
        {
            _httpSemaphore.Release();
        }
    }

    private async Task ScanPortsAsync(ScanResult result)
    {
        var ports = new[] { 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443 };
        var openPorts = new ConcurrentBag<int>();

        var tasks = ports.Select(async port =>
        {
            await _portSemaphore.WaitAsync();
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(800));
                
                var hostEntry = await Dns.GetHostEntryAsync(new Uri(result.Target).Host, cts.Token);
                var connectTask = socket.ConnectAsync(hostEntry.AddressList[0], port);
                
                if (await Task.WhenAny(connectTask, Task.Delay(800, cts.Token)) == connectTask)
                {
                    openPorts.Add(port);
                    Console.WriteLine($"✅ Port {port} OPEN");
                }
            }
            catch { }
            finally
            {
                _portSemaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        result.Ports = openPorts.OrderBy(p => p).ToList();
    }

    private async Task ScanDirectoriesAsync(ScanResult result)
    {
        var dirs = new[] { "admin/", "administrator/", "api/", "login/", "wp-admin/", "config/", "backup/" };
        var foundDirs = new ConcurrentBag<DirectoryInfo>();

        var tasks = dirs.Select(async dir =>
        {
            try
            {
                await _httpSemaphore.WaitAsync();
                var url = new Uri(new Uri(result.Target), dir).ToString();
                using var resp = await _httpClient.GetAsync(url);
                
                if (resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.Forbidden)
                {
                    foundDirs.Add(new DirectoryInfo 
                    { 
                        Path = dir, 
                        StatusCode = (int)resp.StatusCode,
                        ContentLength = resp.Content.Headers.ContentLength ?? 0 
                    });
                    Console.WriteLine($"📁 {dir} ({resp.StatusCode})");
                }
            }
            catch { }
            finally
            {
                _httpSemaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        result.Directories = foundDirs.ToList();
    }

    private async Task ScanTechnologiesAsync(ScanResult result)
    {
        try
        {
            await _httpSemaphore.WaitAsync();
            using var resp = await _httpClient.GetAsync(result.Target);
            var html = await resp.Content.ReadAsStringAsync();

            var techs = new List<string>();
            if (Regex.IsMatch(html, @"wp-content|wp-includes|wp-json", RegexOptions.IgnoreCase))
                techs.Add("WordPress");
            if (Regex.IsMatch(html, @"nginx", RegexOptions.IgnoreCase))
                techs.Add("Nginx");
            if (Regex.IsMatch(html, @"apache", RegexOptions.IgnoreCase))
                techs.Add("Apache");

            result.Technologies = techs;
            _httpSemaphore.Release();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Tech scan: {ex.Message}");
        }
    }

    public async Task GenerateReportsAsync(ScanResult result)
    {
        var report = new
        {
            target = result.Target,
            timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"),
            modules = new
            {
                headers = result.Headers,
                ports = result.Ports,
                directories = result.Directories,
                technologies = result.Technologies
            },
            risk_assessment = result.Risk
        };

        // JSON Report
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions 
        { 
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
        await File.WriteAllTextAsync("reports/report.json", json);

        // HTML Report
        var htmlColor = result.Risk.Level switch
        {
            "HIGH" => "#f44336",
            "MEDIUM" => "#ff9800",
            _ => "#4caf50"
        };

        var html = $@"<!DOCTYPE html>
<html>
<head>
    <title>WebRecon v3.0 - {result.Target}</title>
    <style>
        body {{ font-family: 'Fira Code', monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; line-height: 1.6; }}
        .header {{ background: #21262d; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem; }}
        .risk {{ color: {htmlColor}; font-weight: bold; font-size: 1.2em; }}
        pre {{ background: #161b22; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
        h1 {{ color: #58a6ff; margin-top: 0; }}
        .issues {{ background: #1f2937; padding: 1rem; border-left: 4px solid {htmlColor}; }}
    </style>
</head>
<body>
    <div class='header'>
        <h1>🔍 WebRecon Enterprise v3.0</h1>
        <p><strong>{result.Target}</strong></p>
        <p class='risk'>{result.Risk.Level} Risk | {result.Risk.Score}/100</p>
    </div>
    
    <pre>{json}</pre>
    
    {(result.Risk.Issues.Any() ? $"<div class='issues'><strong>Top Issues:</strong><ul>{string.Join("", result.Risk.Issues.Select(i => $"<li>{i}</li>"))}</ul></div>" : "")}
    
    <small style='opacity: 0.6;'>Generated: {DateTime.Now} | LaxenTgit</small>
</body>
</html>";

        await File.WriteAllTextAsync("reports/report.html", html);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _httpClient?.Dispose();
            _httpSemaphore?.Dispose();
            _portSemaphore?.Dispose();
            _disposed = true;
        }
    }
}

public class ScanResult
{
    public string Target { get; set; } = "";
    public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<int> Ports { get; set; } = new();
    public List<DirectoryInfo> Directories { get; set; } = new();
    public List<string> Technologies { get; set; } = new();
    public RiskAssessment Risk { get; set; } = new();
}

public class DirectoryInfo
{
    public string Path { get; set; } = "";
    public int StatusCode { get; set; }
    public long ContentLength { get; set; }
}

public static class RiskCalculator
{
    public static RiskAssessment Calculate(ScanResult result)
    {
        var assessment = new RiskAssessment();
        
        // Port Analysis
        var highRiskPorts = result.Ports.Where(p => p is 21 or 22 or 23 or 3389).ToList();
        if (highRiskPorts.Any())
        {
            assessment.Score += highRiskPorts.Count * 20;
            assessment.Issues.AddRange(highRiskPorts.Select(p => $"CRITICAL: Port {p} exposed"));
        }

        // Directory Exposure
        if (result.Directories.Any())
        {
            assessment.Score += result.Directories.Count * 10;
            assessment.Issues.Add($"{result.Directories.Count} directories accessible");
        }

        // Security Headers
        if (!result.Headers.ContainsKey("strict-transport-security"))
            assessment.Issues.Add("Missing HSTS");
        if (!result.Headers.ContainsKey("x-frame-options"))
            assessment.Issues.Add("Missing X-Frame-Options");

        // Tech Stack
        if (result.Technologies.Contains("WordPress"))
            assessment.Issues.Add("WordPress detected - verify plugins");

        assessment.Score = Math.Min(assessment.Score, 100);
        assessment.Level = assessment.Score switch
        {
            < 30 => "LOW",
            < 70 => "MEDIUM",
            _ => "HIGH"
        };

        return assessment;
    }
}

public class RiskAssessment
{
    public int Score { get; set; }
    public string Level { get; set; } = "LOW";
    public List<string> Issues { get; set; } = new();
}

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("=== Recon Tool v1.0 ===");

        if (args.Length == 0)
        {
            Console.WriteLine("Kullanım: dotnet run <target_url>");
            return;
        }

        var target = FixUrl(args[0]);
        if (string.IsNullOrEmpty(target))
        {
            Console.WriteLine("[-] Geçersiz URL girildi.");
            return;
        }

        Console.WriteLine($"[*] Hedef: {target}");
        
        if (!Directory.Exists("reports"))
            Directory.CreateDirectory("reports");

        using var scanner = new WebScanner(target);
        var result = await scanner.RunAsync();
        
        await scanner.SaveReportsAsync(result);

        Console.WriteLine($"\n[+] Tarama bitti. Risk Seviyesi: {result.Risk.Level} ({result.Risk.Score}/100)");
        Console.WriteLine("[+] Raporlar 'reports' klasörüne kaydedildi.");
    }

    private static string FixUrl(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return null;
        
        input = input.Trim().TrimEnd('/');
        if (!input.StartsWith("http://") && !input.StartsWith("https://"))
        {
            input = "https://" + input;
        }

        return Uri.TryCreate(input, UriKind.Absolute, out var uri) ? uri.ToString() : null;
    }
}

public class WebScanner : IDisposable
{
    private readonly HttpClient _client;
    private readonly SemaphoreSlim _httpLimiter = new(5, 5);
    private readonly SemaphoreSlim _portLimiter = new(50, 50);
    private readonly string _target;

    public WebScanner(string target)
    {
        _target = target;
        _client = new HttpClient
        {
            BaseAddress = new Uri(target),
            Timeout = TimeSpan.FromSeconds(10)
        };
        
        // Sunucu engeline takılmamak için varsayılan User-Agent
        _client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
    }

    public async Task<ScanResult> RunAsync()
    {
        var result = new ScanResult { Target = _target };

        // paraler çalışma
        var tasks = new Task[]
        {
            CheckHeadersAsync(result),
            ScanPortsAsync(result),
            CheckDirectoriesAsync(result),
            DetectTechAsync(result)
        };

        await Task.WhenAll(tasks);
        
        result.Risk = RiskCalculator.Evaluate(result);
        return result;
    }

    private async Task CheckHeadersAsync(ScanResult result)
    {
        await _httpLimiter.WaitAsync();
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Head, _target);
            using var res = await _client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead);

            foreach (var header in res.Headers)
            {
                result.Headers[header.Key] = string.Join(", ", header.Value);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Header tarama hatası: {ex.Message}");
        }
        finally
        {
            _httpLimiter.Release();
        }
    }

    private async Task ScanPortsAsync(ScanResult result)
    {
        // common servis portları
        int[] targetPorts = { 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443 };
        var foundPorts = new ConcurrentBag<int>();

        var tasks = targetPorts.Select(async port =>
        {
            await _portLimiter.WaitAsync();
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                using var cts = new CancellationTokenSource(1000); // 1 sn timeout

                var host = new Uri(_target).Host;
                var ipList = await Dns.GetHostAddressesAsync(host, cts.Token);
                
                if (ipList.Length == 0) return;

                var connectTask = socket.ConnectAsync(ipList[0], port);
                if (await Task.WhenAny(connectTask, Task.Delay(1000, cts.Token)) == connectTask && socket.Connected)
                {
                    foundPorts.Add(port);
                    Console.WriteLine($"  [+] Port {port} Açık");
                }
            }
            catch
            {
                // Bağlantı reddedildi
            }
            finally
            {
                _portLimiter.Release();
            }
        });

        await Task.WhenAll(tasks);
        result.Ports = foundPorts.OrderBy(p => p).ToList();
    }

    private async Task CheckDirectoriesAsync(ScanResult result)
    {
        string[] commonPaths = { "admin/", "administrator/", "api/", "login/", "wp-admin/", "config/", "backup/" };
        var list = new ConcurrentBag<PathInfo>();

        var tasks = commonPaths.Select(async path =>
        {
            await _httpLimiter.WaitAsync();
            try
            {
                var fullUrl = new Uri(new Uri(_target), path).ToString();
                using var res = await _client.GetAsync(fullUrl);

                if (res.IsSuccessStatusCode || res.StatusCode == HttpStatusCode.Forbidden)
                {
                    list.Add(new PathInfo
                    {
                        Path = path,
                        StatusCode = (int)res.StatusCode,
                        Size = res.Content.Headers.ContentLength ?? 0
                    });
                    Console.WriteLine($"  [+] Bulundu: /{path} (HTTP {(int)res.StatusCode})");
                }
            }
            catch
            {
                // istek haatası
            }
            finally
            {
                _httpLimiter.Release();
            }
        });

        await Task.WhenAll(tasks);
        result.Directories = list.ToList();
    }

    private async Task DetectTechAsync(ScanResult result)
    {
        await _httpLimiter.WaitAsync();
        try
        {
            using var res = await _client.GetAsync(_target);
            var html = await res.Content.ReadAsStringAsync();

            var detected = new List<string>();

            if (Regex.IsMatch(html, @"wp-content|wp-includes", RegexOptions.IgnoreCase))
                detected.Add("WordPress");
            if (Regex.IsMatch(html, @"nginx", RegexOptions.IgnoreCase))
                detected.Add("Nginx");
            if (Regex.IsMatch(html, @"apache", RegexOptions.IgnoreCase))
                detected.Add("Apache");

            result.Technologies = detected;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Teknoloji tespiti hatası: {ex.Message}");
        }
        finally
        {
            _httpLimiter.Release();
        }
    }

    public async Task SaveReportsAsync(ScanResult result)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        var json = JsonSerializer.Serialize(result, options);
        
        await File.WriteAllTextAsync("reports/report.json", json);

        var html = $@"<!DOCTYPE html>
<html lang='tr'>
<head>
    <meta charset='UTF-8'>
    <title>Tarama Raporu - {result.Target}</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; background: #f4f4f9; color: #333; }}
        .card {{ background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        pre {{ background: #272822; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .badge {{ padding: 5px 10px; border-radius: 3px; color: #fff; font-weight: bold; }}
        .HIGH {{ background: #e74c3c; }}
        .MEDIUM {{ background: #f39c12; }}
        .LOW {{ background: #2ecc71; }}
    </style>
</head>
<body>
    <div class='card'>
        <h2>Tarama Özeti: {result.Target}</h2>
        <p>Risk Durumu: <span class='badge {result.Risk.Level}'>{result.Risk.Level} ({result.Risk.Score}/100)</span></p>
        <hr>
        <h3>Bulgular (JSON)</h3>
        <pre>{json}</pre>
    </div>
</body>
</html>";

        await File.WriteAllTextAsync("reports/report.html", html);
    }

    public void Dispose()
    {
        _client?.Dispose();
        _httpLimiter?.Dispose();
        _portLimiter?.Dispose();
    }
}

public class ScanResult
{
    public string Target { get; set; } = "";
    public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<int> Ports { get; set; } = new();
    public List<PathInfo> Directories { get; set; } = new();
    public List<string> Technologies { get; set; } = new();
    public RiskInfo Risk { get; set; } = new();
}

public class PathInfo
{
    public string Path { get; set; } = "";
    public int StatusCode { get; set; }
    public long Size { get; set; }
}

public class RiskInfo
{
    public int Score { get; set; }
    public string Level { get; set; } = "LOW";
    public List<string> Findings { get; set; } = new();
}

public static class RiskCalculator
{
    public static RiskInfo Evaluate(ScanResult scan)
    {
        var risk = new RiskInfo();

        // Hasas port 
        var openCriticalPorts = scan.Ports.Where(p => p is 21 or 22 or 23 or 3389).ToList();
        if (openCriticalPorts.Count > 0)
        {
            risk.Score += openCriticalPorts.Count * 20;
            risk.Findings.Add($"Açık kritik portlar: {string.Join(", ", openCriticalPorts)}");
        }

        // Acık dizinler
        if (scan.Directories.Count > 0)
        {
            risk.Score += scan.Directories.Count * 10;
            risk.Findings.Add($"{scan.Directories.Count} adet hassas/erişilebilir dizin bulundu.");
        }

        // Header -
        if (!scan.Headers.ContainsKey("Strict-Transport-Security"))
            risk.Findings.Add("HSTS başlığı eksik.");

        risk.Score = Math.Min(risk.Score, 100);
        risk.Level = risk.Score switch
        {
            >= 70 => "HIGH",
            >= 30 => "MEDIUM",
            _ => "LOW"
        };

        return risk;
    }
}

/*
 * ==============================================================================
 * PROJECT     : Cat-System PRO (Advanced Windows Optimizer & Privacy Guard)
 * DEVELOPER   : Tc4dy
 * DESCRIPTION : Disables Windows telemetry/spyware and optimizes system 
 * performance in a single, unified environment
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using System.Management;
using System.Net.NetworkInformation;
[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace CatSystemCore
{
    public interface IModule
    {
        string ModuleName { get; }
        void Execute();
    }

    public enum LogType
    {
        Info,
        Success,
        Warning,
        Error,
        System,
        Critical
    }

    public static class Win32Api
    {
        [DllImport("psapi.dll", SetLastError = true)]
        public static extern int EmptyWorkingSet(IntPtr hwProc);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize);

        [DllImport("kernel32.dll")]
        public static extern bool SetPriorityClass(IntPtr handle, uint priorityClass);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtSetSystemInformation(int SystemInformationClass, IntPtr SystemInfo, int SystemInfoLength);

        public const uint IDLE_PRIORITY_CLASS = 0x0040;
        public const uint BELOW_NORMAL_PRIORITY_CLASS = 0x4000;
        public const uint NORMAL_PRIORITY_CLASS = 0x0020;
        public const uint ABOVE_NORMAL_PRIORITY_CLASS = 0x8000;
        public const uint HIGH_PRIORITY_CLASS = 0x0080;

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_CACHE_INFORMATION
        {
            public uint CurrentSize;
            public uint PeakSize;
            public uint PageFaultCount;
            public uint MinimumWorkingSet;
            public uint MaximumWorkingSet;
            public uint Unused1;
            public uint Unused2;
            public uint Unused3;
            public uint Unused4;
        }
    }

    public class Logger
    {
        private static Logger _instance;
        private static readonly object _lock = new object();
        public static Logger Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_lock)
                    {
                        if (_instance == null)
                            _instance = new Logger();
                    }
                }
                return _instance;
            }
        }

        public void Log(string message, LogType type, string emoji = "")
        {
            lock (_lock)
            {
                switch (type)
                {
                    case LogType.Info:
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.Write($"[INFO] {emoji} ");
                        break;
                    case LogType.Success:
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write($"[✓] {emoji} ");
                        break;
                    case LogType.Warning:
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.Write($"[!] {emoji} ");
                        break;
                    case LogType.Error:
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Write($"[✗] {emoji} ");
                        break;
                    case LogType.System:
                        Console.ForegroundColor = ConsoleColor.Magenta;
                        Console.Write($"[SYS] {emoji} ");
                        break;
                    case LogType.Critical:
                        Console.ForegroundColor = ConsoleColor.DarkRed;
                        Console.Write($"[!!!] {emoji} ");
                        break;
                }
                Console.WriteLine(message);
                Console.ResetColor();
            }
        }

        public void Header(string title, string emoji = "")
        {
            lock (_lock)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"\n╔══════════════════════════════════════════════════════╗");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine($"║  {emoji} {title.ToUpper().PadRight(46)} ║");
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"╚══════════════════════════════════════════════════════╝");
                Console.ResetColor();
            }
        }

        public void Progress(string message)
        {
            lock (_lock)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine($"    → {message}");
                Console.ResetColor();
            }
        }
    }

    public class Localization
    {
        public static string Language = "EN";
        private static readonly Dictionary<string, Dictionary<string, string>> Texts = new Dictionary<string, Dictionary<string, string>>()
        {
            {
                "TR", new Dictionary<string, string> {
                    { "welcome", "Cat-System Çekirdeği Yüklendi." },
                    { "admin_err", "YÖNETİCİ İZNİ GEREKLİ! Lütfen sağ tıklayıp Yönetici olarak çalıştırın." },
                    { "menu_title", "ANA KONTROL PANELİ" },
                    { "opt_1", "[1] GHOST PROTOCOL (Gizlilik ve Telemetri Engelleme)" },
                    { "opt_2", "[2] SCULPTOR ENGINE (RAM ve İşlemci Optimizasyonu)" },
                    { "opt_3", "[3] NET BOOSTER (Ağ ve DNS Yapılandırması)" },
                    { "opt_0", "[0] SİSTEMİ KAPAT" },
                    { "select", "Komut Bekleniyor: " },
                    { "proc_start", "İşlem başlatılıyor..." },
                    { "proc_complete", "Modül çalışması tamamlandı." },
                    { "reg_success", "Kayıt Defteri anahtarı işlendi: " },
                    { "reg_fail", "Kayıt Defteri erişim hatası: " },
                    { "ram_cleared", "Bellek optimize edildi. Geri kazanılan: " },
                    { "net_flush", "DNS Önbelleği temizlendi." },
                    { "net_reset", "Ağ yapılandırması sıfırlandı." },
                    { "sys_analysis", "Sistem analizi yapılıyor..." },
                    { "optimization_start", "Optimizasyon başlatıldı" },
                    { "task_completed", "Görev tamamlandı" }
                }
            },
            {
                "EN", new Dictionary<string, string> {
                    { "welcome", "Cat-System Core Loaded." },
                    { "admin_err", "ADMINISTRATOR PRIVILEGES REQUIRED! Please run as Administrator." },
                    { "menu_title", "MAIN CONTROL PANEL" },
                    { "opt_1", "[1] GHOST PROTOCOL (Privacy & Telemetry Blocker)" },
                    { "opt_2", "[2] SCULPTOR ENGINE (RAM & CPU Optimization)" },
                    { "opt_3", "[3] NET BOOSTER (Network & DNS Configuration)" },
                    { "opt_0", "[0] SHUTDOWN SYSTEM" },
                    { "select", "Awaiting Command: " },
                    { "proc_start", "Initiating process..." },
                    { "proc_complete", "Module execution finished." },
                    { "reg_success", "Registry key processed: " },
                    { "reg_fail", "Registry access failed: " },
                    { "ram_cleared", "Memory optimized. Reclaimed: " },
                    { "net_flush", "DNS Cache flushed." },
                    { "net_reset", "Network configuration reset." },
                    { "sys_analysis", "Performing system analysis..." },
                    { "optimization_start", "Optimization initiated" },
                    { "task_completed", "Task completed" }
                }
            }
        };

        public static string Get(string key)
        {
            if (Texts.ContainsKey(Language) && Texts[Language].ContainsKey(key))
                return Texts[Language][key];
            return "MISSING_TEXT";
        }
    }

    public class SystemAnalyzer
    {
        public static (long TotalRAM, long AvailableRAM, double CPUUsage) GetSystemMetrics()
        {
            try
            {
                var computerInfo = new Microsoft.VisualBasic.Devices.ComputerInfo();
                long totalRAM = (long)computerInfo.TotalPhysicalMemory;
                long availableRAM = (long)computerInfo.AvailablePhysicalMemory;

                var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue();
                Thread.Sleep(100);
                double cpuUsage = cpuCounter.NextValue();

                return (totalRAM, availableRAM, cpuUsage);
            }
            catch
            {
                return (0, 0, 0);
            }
        }

        public static int GetActiveProcessCount()
        {
            try
            {
                return Process.GetProcesses().Length;
            }
            catch
            {
                return 0;
            }
        }
    }

    public class RegistryHandler
    {
        public static bool SetKey(string root, string subKey, string keyName, object value, RegistryValueKind kind)
        {
            try
            {
                RegistryKey baseKey = root == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                using (RegistryKey rk = baseKey.CreateSubKey(subKey, true))
                {
                    if (rk != null)
                    {
                        rk.SetValue(keyName, value, kind);
                        Logger.Instance.Progress($"{Localization.Get("reg_success")} {keyName}");
                        return true;
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Logger.Instance.Log($"{Localization.Get("reg_fail")} Access denied to {keyName}", LogType.Error);
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"{Localization.Get("reg_fail")} {ex.Message}", LogType.Error);
            }
            return false;
        }

        public static object GetKey(string root, string subKey, string keyName, object defaultValue = null)
        {
            try
            {
                RegistryKey baseKey = root == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                using (RegistryKey rk = baseKey.OpenSubKey(subKey, false))
                {
                    if (rk != null)
                    {
                        return rk.GetValue(keyName, defaultValue);
                    }
                }
            }
            catch { }
            return defaultValue;
        }
    }

    public class GhostProtocol : IModule
    {
        public string ModuleName => "Ghost Protocol";

        private int _operationsCompleted = 0;
        private int _totalOperations = 0;

        public void Execute()
        {
            Logger.Instance.Header(ModuleName, "🛡️");
            Logger.Instance.Log(Localization.Get("sys_analysis"), LogType.System);
            
            Thread.Sleep(800);

            var tweaks = new Dictionary<string, Action>
            {
                { "Windows Telemetry", DisableTelemetry },
                { "Advertising Tracking", DisableAds },
                { "Cortana Integration", DisableCortana },
                { "Web Search in Start", DisableBingSearch },
                { "Location Tracking", DisableLocation },
                { "Activity History", DisableActivityHistory },
                { "Feedback Notifications", DisableFeedback },
                { "Consumer Features", DisableConsumerFeatures }
            };

            _totalOperations = tweaks.Count;

            foreach (var tweak in tweaks)
            {
                Logger.Instance.Log($"Processing: {tweak.Key}...", LogType.Info, "🔧");
                try
                {
                    tweak.Value.Invoke();
                    _operationsCompleted++;
                    Thread.Sleep(300);
                }
                catch (Exception ex)
                {
                    Logger.Instance.Log($"Failed to apply {tweak.Key}: {ex.Message}", LogType.Warning);
                }
            }

            Logger.Instance.Log($"{Localization.Get("proc_complete")} [{_operationsCompleted}/{_totalOperations} successful]", LogType.Success, "✓");
        }

        private void DisableTelemetry()
        {
            // Diagnostic Data Collection
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "MaxTelemetryAllowed", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0, RegistryValueKind.DWord);
            
            // Disable DiagTrack service via registry
            RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\DiagTrack", "Start", 4, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\dmwappushservice", "Start", 4, RegistryValueKind.DWord);
        }

        private void DisableAds()
        {
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SilentInstalledAppsEnabled", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled", 0, RegistryValueKind.DWord);
        }

        private void DisableCortana()
        {
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortanaAboveLock", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowSearchToUseLocation", 0, RegistryValueKind.DWord);
        }

        private void DisableBingSearch()
        {
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "DisableWebSearch", 1, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "ConnectedSearchUseWeb", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Search", "BingSearchEnabled", 0, RegistryValueKind.DWord);
        }

        private void DisableLocation()
        {
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", "Deny", RegistryValueKind.String);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location", "Value", "Deny", RegistryValueKind.String);
        }

        private void DisableActivityHistory()
        {
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableActivityFeed", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0, RegistryValueKind.DWord);
        }

        private void DisableFeedback()
        {
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Siuf\Rules", "NumberOfSIUFInPeriod", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DoNotShowFeedbackNotifications", 1, RegistryValueKind.DWord);
        }

        private void DisableConsumerFeatures()
        {
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", 1, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "ContentDeliveryAllowed", 0, RegistryValueKind.DWord);
        }
    }

    public class SculptorEngine : IModule
    {
        public string ModuleName => "System Sculptor";
        private readonly string[] _backgroundProcesses = { "OneDrive", "SkypeApp", "YourPhone", "MicrosoftEdgeUpdate", "XboxGameBar", "GameBar", "PhoneExperienceHost" };
        
        private long _initialMemory = 0;
        private long _finalMemory = 0;
        private int _processesOptimized = 0;

        public void Execute()
        {
            Logger.Instance.Header(ModuleName, "⚡");
            Logger.Instance.Log(Localization.Get("sys_analysis"), LogType.System);

            var (totalRAM, availableRAM, cpuUsage) = SystemAnalyzer.GetSystemMetrics();
            _initialMemory = availableRAM;

            Logger.Instance.Progress($"Total RAM: {totalRAM / 1024 / 1024 / 1024}GB | Available: {availableRAM / 1024 / 1024}MB");
            Logger.Instance.Progress($"CPU Usage: {cpuUsage:F1}% | Processes: {SystemAnalyzer.GetActiveProcessCount()}");
            Thread.Sleep(500);

            Logger.Instance.Log("Initiating optimization sequence...", LogType.Info, "🔧");
            
            PerformProcessOptimization();
            PerformMemoryOptimization();
            OptimizeSystemCache();
            ConfigureHighPerformance();

            Thread.Sleep(500);
            var (_, finalAvailable, _) = SystemAnalyzer.GetSystemMetrics();
            _finalMemory = finalAvailable;

            long memoryGain = (_finalMemory - _initialMemory) / 1024 / 1024;
            
            Logger.Instance.Log($"{Localization.Get("proc_complete")}", LogType.Success, "✓");
            Logger.Instance.Log($"Memory reclaimed: {Math.Max(0, memoryGain)}MB | Processes optimized: {_processesOptimized}", LogType.Success, "📊");
        }

        private void PerformProcessOptimization()
        {
            Logger.Instance.Log("Analyzing background processes...", LogType.Info, "🔍");
            
            foreach (var procName in _backgroundProcesses)
            {
                try
                {
                    Process[] processes = Process.GetProcessesByName(procName);
                    foreach (var p in processes)
                    {
                        try
                        {
                            if (!p.HasExited && p.Responding)
                            {
                                p.PriorityClass = ProcessPriorityClass.Idle;
                                Win32Api.EmptyWorkingSet(p.Handle);
                                _processesOptimized++;
                                Logger.Instance.Progress($"Optimized: {p.ProcessName} (PID: {p.Id})");
                            }
                        }
                        catch (InvalidOperationException) { }
                        catch (System.ComponentModel.Win32Exception) { }
                    }
                }
                catch { }
            }

            if (_processesOptimized == 0)
            {
                Logger.Instance.Log("No background processes found for optimization", LogType.Info);
            }
        }

        private void PerformMemoryOptimization()
        {
            Logger.Instance.Log("Optimizing system memory allocation...", LogType.Info, "🧠");
            
            long totalTrimmed = 0;
            int processCount = 0;
            Process[] allProcesses = Process.GetProcesses();
            
            // Focus on high memory consumers that are safe to trim
            var sortedProcesses = allProcesses
                .Where(p => !p.HasExited)
                .OrderByDescending(p => {
                    try { return p.WorkingSet64; }
                    catch { return 0; }
                })
                .Take(50)
                .ToList();

            foreach (Process p in sortedProcesses)
            {
                try
                {
                    if (!p.HasExited && !IsCriticalProcess(p.ProcessName))
                    {
                        long beforeTrim = p.WorkingSet64;
                        Win32Api.EmptyWorkingSet(p.Handle);
                        
                        Thread.Sleep(10);
                        
                        long afterTrim = p.WorkingSet64;
                        long trimmed = beforeTrim - afterTrim;
                        
                        if (trimmed > 0)
                        {
                            totalTrimmed += trimmed;
                            processCount++;
                        }
                    }
                }
                catch { }
            }

            double mbTrimmed = totalTrimmed / 1024.0 / 1024.0;
            Logger.Instance.Progress($"Memory trim completed: ~{mbTrimmed:F1}MB from {processCount} processes");
        }

        private bool IsCriticalProcess(string processName)
        {
            string[] criticalProcesses = { "System", "csrss", "smss", "services", "lsass", "svchost", "dwm", "explorer", "winlogon" };
            return criticalProcesses.Any(cp => processName.Equals(cp, StringComparison.OrdinalIgnoreCase));
        }

        private void OptimizeSystemCache()
        {
            Logger.Instance.Log("Configuring system file cache...", LogType.Info, "💾");
            
            try
            {
                // Configure system file cache behavior for better performance
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "LargeSystemCache", 0, RegistryValueKind.DWord);
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "ClearPageFileAtShutdown", 0, RegistryValueKind.DWord);
                
                Logger.Instance.Progress("System cache parameters optimized");
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"Cache optimization failed: {ex.Message}", LogType.Warning);
            }
        }

        private void ConfigureHighPerformance()
        {
            Logger.Instance.Log("Configuring power and performance settings...", LogType.Info, "⚡");
            
            try
            {
                // Set High Performance power plan (GUID for High Performance)
                var psi = new ProcessStartInfo
                {
                    FileName = "powercfg.exe",
                    Arguments = "/setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                
                using (var process = Process.Start(psi))
                {
                    process.WaitForExit(5000);
                    if (process.ExitCode == 0)
                    {
                        Logger.Instance.Progress("Power plan set to High Performance");
                    }
                }

                // Disable processor throttling
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec", "Attributes", 2, RegistryValueKind.DWord);
                
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"Power configuration partial failure: {ex.Message}", LogType.Warning);
            }
        }
    }

    public class NetworkBooster : IModule
    {
        public string ModuleName => "Net Booster";
        private int _operationsCompleted = 0;

        public void Execute()
        {
            Logger.Instance.Header(ModuleName, "🚀");
            Logger.Instance.Log("Analyzing network configuration...", LogType.System);
            
            Thread.Sleep(600);
            
            DisplayNetworkInfo();
            
            Logger.Instance.Log("Applying TCP/IP optimizations...", LogType.Info, "🔧");
            
            FlushDNSCache();
            ResetNetworkStack();
            OptimizeTCPParameters();
            ConfigureDNSPriority();
            
            Logger.Instance.Log($"{Localization.Get("proc_complete")} [{_operationsCompleted} operations successful]", LogType.Success, "✓");
            Logger.Instance.Log("Network configuration optimized for performance", LogType.Success, "📡");
        }

        private void DisplayNetworkInfo()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.OperationalStatus == OperationalStatus.Up && 
                                 ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .ToList();

                if (interfaces.Any())
                {
                    var primaryInterface = interfaces.First();
                    Logger.Instance.Progress($"Active Interface: {primaryInterface.Name}");
                    Logger.Instance.Progress($"Speed: {primaryInterface.Speed / 1_000_000}Mbps | Type: {primaryInterface.NetworkInterfaceType}");
                }
            }
            catch { }
        }

        private void FlushDNSCache()
        {
            if (RunCommand("ipconfig", "/flushdns", false))
            {
                Logger.Instance.Progress(Localization.Get("net_flush"));
                _operationsCompleted++;
            }
        }

        private void ResetNetworkStack()
        {
            Logger.Instance.Log("Resetting network stack components...", LogType.Info);
            
            if (RunCommand("netsh", "winsock reset", false))
            {
                Logger.Instance.Progress("Winsock catalog reset successful");
                _operationsCompleted++;
            }
            
            if (RunCommand("netsh", "int ip reset", false))
            {
                Logger.Instance.Progress("TCP/IP stack reset successful");
                _operationsCompleted++;
            }

            if (RunCommand("netsh", "int tcp reset", false))
            {
                Logger.Instance.Progress("TCP configuration reset successful");
                _operationsCompleted++;
            }
        }

        private void OptimizeTCPParameters()
        {
            Logger.Instance.Log("Configuring TCP parameters for performance...", LogType.Info, "⚙️");
            
            try
            {
                // TCP Auto-Tuning (Windows 10/11 handles this well, ensure it's enabled)
                RunCommand("netsh", "int tcp set global autotuninglevel=normal", false);
                
                // Enable TCP Window Scaling
                RunCommand("netsh", "int tcp set global timestamps=enabled", false);
                
                // Optimize for network throughput
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Tcp1323Opts", 1, RegistryValueKind.DWord);
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpMaxDupAcks", 2, RegistryValueKind.DWord);
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TCPNoDelay", 1, RegistryValueKind.DWord);
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "TcpAckFrequency", 1, RegistryValueKind.DWord);
                
                // Network throttling index (disable throttling)
                RegistryHandler.SetKey("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NetworkThrottlingIndex", 0xffffffff, RegistryValueKind.DWord);
                
                Logger.Instance.Progress("TCP/IP parameters optimized");
                _operationsCompleted++;
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"TCP optimization warning: {ex.Message}", LogType.Warning);
            }
        }

        private void ConfigureDNSPriority()
        {
            Logger.Instance.Log("Optimizing DNS resolution...", LogType.Info, "🌐");
            
            try
            {
                // DNS cache settings
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "MaxCacheTtl", 86400, RegistryValueKind.DWord);
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "MaxNegativeCacheTtl", 300, RegistryValueKind.DWord);
                
                Logger.Instance.Progress("DNS cache optimized for faster lookups");
                _operationsCompleted++;
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"DNS configuration warning: {ex.Message}", LogType.Warning);
            }
        }

        private bool RunCommand(string cmd, string args, bool showOutput = false)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = cmd,
                    Arguments = args,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                    };

                               using (var process = Process.Start(psi))
            {
                process.WaitForExit(10000);
                
                if (showOutput)
                {
                    string output = process.StandardOutput.ReadToEnd();
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        Logger.Instance.Progress(output.Trim());
                    }
                }
                
                return process.ExitCode == 0;
            }
        }
        catch (Exception ex)
        {
            Logger.Instance.Log($"Command execution failed ({cmd} {args}): {ex.Message}", LogType.Error);
            return false;
        }
    }
}

class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.Title = "Cat-System | Professional Optimizer";
        
        if (!IsAdministrator())
        {
            Console.BackgroundColor = ConsoleColor.DarkRed;
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"\n  ⚠️  {Localization.Get("admin_err")}  \n");
            Console.ResetColor();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            return;
        }

        SelectLanguage();

        while (true)
        {
            try
            {
                Console.Clear();
                DrawUI();
                
                Console.Write(Localization.Get("select"));
                string input = Console.ReadLine()?.Trim();

                IModule module = null;

                switch (input)
                {
                    case "1":
                        module = new GhostProtocol();
                        break;
                    case "2":
                        module = new SculptorEngine();
                        break;
                    case "3":
                        module = new NetworkBooster();
                        break;
                    case "0":
                        AnimateExit();
                        return;
                    default:
                        Logger.Instance.Log("Invalid selection. Please try again.", LogType.Warning, "⚠️");
                        Thread.Sleep(1500);
                        continue;
                }

                if (module != null)
                {
                    Console.Clear();
                    
                    try
                    {
                        module.Execute();
                    }
                    catch (Exception ex)
                    {
                        Logger.Instance.Log($"Module execution error: {ex.Message}", LogType.Error, "✗");
                    }
                    
                    Console.WriteLine("\n╔══════════════════════════════════════════════════════╗");
                    Console.WriteLine("║  Press ANY KEY to return to Main Menu               ║");
                    Console.WriteLine("╚══════════════════════════════════════════════════════╝");
                    Console.ReadKey();
                }
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"System error: {ex.Message}", LogType.Critical);
                Thread.Sleep(2000);
            }
        }
    }

    static bool IsAdministrator()
    {
        try
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        catch
        {
            return false;
        }
    }

    static void SelectLanguage()
    {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n╔══════════════════════════════════════╗");
        Console.WriteLine("║     LANGUAGE / DİL SEÇİMİ           ║");
        Console.WriteLine("╚══════════════════════════════════════╝\n");
        Console.ResetColor();
        Console.WriteLine("  [1] English");
        Console.WriteLine("  [2] Türkçe\n");
        Console.Write("Select / Seçin: ");
        
        var choice = Console.ReadLine()?.Trim();
        Localization.Language = (choice == "2") ? "TR" : "EN";
        
        Console.Clear();
    }

    static void DrawUI()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(@"

/ / / /    / /  / /  ____ ___
/ /   / __ / __/____\__ \/ / / / ___/ __/ _ \/ __  
/ /__/ // / //// / // (  ) //  / / / / / /
_/_,/_/     //_, /__/_/_// // //
/_/
");
Console.WriteLine("══════════════════════════════════════════════════════════");
Console.ForegroundColor = ConsoleColor.White;
Console.WriteLine($" 🔰 {Localization.Get("welcome")}");
Console.ForegroundColor = ConsoleColor.DarkGray;
Console.WriteLine($" 💻 System: {Environment.OSVersion.VersionString}");
Console.WriteLine($" 👤 User: {Environment.UserName} | Admin Mode");
Console.WriteLine($" 🛠️  Architect: Tc4dy | Version 2.0");
Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("══════════════════════════════════════════════════════════");
Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"\n{Localization.Get("menu_title")}");
        Console.ResetColor();
        Console.WriteLine($"  {Localization.Get("opt_1")}");
        Console.WriteLine($"  {Localization.Get("opt_2")}");
        Console.WriteLine($"  {Localization.Get("opt_3")}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("──────────────────────────────────────────────────────────");
        Console.ResetColor();
        Console.WriteLine($"  {Localization.Get("opt_0")}");
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("──────────────────────────────────────────────────────────");
        Console.ResetColor();
    }

    static void AnimateExit()
    {
        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n╔══════════════════════════════════════════════════════╗");
        Console.WriteLine("║         Shutting down Cat-System...                  ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════╝");
        Console.ResetColor();
        
        for (int i = 0; i < 3; i++)
        {
            Thread.Sleep(400);
            Console.Write(".");
        }
        
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("\n\n✓ System terminated successfully.");
        Console.ResetColor();
        Thread.Sleep(800);
    }
  }
}
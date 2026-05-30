using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using System.Net.NetworkInformation;
[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace CatSystemCore
{
    public interface IModule
    {
        string ModuleName { get; }
        bool Execute();
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

        [DllImport("kernel32.dll")]
        public static extern bool SetPriorityClass(IntPtr handle, uint priorityClass);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        public const uint IDLE_PRIORITY_CLASS = 0x0040;
        public const uint BELOW_NORMAL_PRIORITY_CLASS = 0x4000;
        public const uint NORMAL_PRIORITY_CLASS = 0x0020;
        public const uint ABOVE_NORMAL_PRIORITY_CLASS = 0x8000;
        public const uint HIGH_PRIORITY_CLASS = 0x0080;
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
                    lock (_lock)
                        if (_instance == null)
                            _instance = new Logger();
                return _instance;
            }
        }

        public void Log(string message, LogType type, string emoji = "")
        {
            lock (_lock)
            {
                switch (type)
                {
                    case LogType.Info:     Console.ForegroundColor = ConsoleColor.Cyan;    Console.Write($"[INFO] {emoji} "); break;
                    case LogType.Success:  Console.ForegroundColor = ConsoleColor.Green;   Console.Write($"[OK] {emoji} ");   break;
                    case LogType.Warning:  Console.ForegroundColor = ConsoleColor.Yellow;  Console.Write($"[!] {emoji} ");    break;
                    case LogType.Error:    Console.ForegroundColor = ConsoleColor.Red;     Console.Write($"[X] {emoji} ");    break;
                    case LogType.System:   Console.ForegroundColor = ConsoleColor.Magenta; Console.Write($"[SYS] {emoji} "); break;
                    case LogType.Critical: Console.ForegroundColor = ConsoleColor.DarkRed; Console.Write($"[!!!] {emoji} "); break;
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
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"    -> {message}");
            Console.ResetColor();
        }
    }

    public class SystemAnalyzer
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        public static (long TotalRAM, long AvailableRAM, double CPUUsage) GetSystemMetrics()
        {
            try
            {
                var mem = new MEMORYSTATUSEX { dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(MEMORYSTATUSEX)) };
                GlobalMemoryStatusEx(ref mem);

                var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
                cpuCounter.NextValue();
                Thread.Sleep(1000);
                double cpuUsage = cpuCounter.NextValue();

                return ((long)mem.ullTotalPhys, (long)mem.ullAvailPhys, cpuUsage);
            }
            catch
            {
                return (0, 0, 0);
            }
        }

        public static int GetActiveProcessCount()
        {
            try { return Process.GetProcesses().Length; }
            catch { return 0; }
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
                        Logger.Instance.Progress($"Registry key set: {keyName}");
                        return true;
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                Logger.Instance.Log($"Registry access denied: {keyName}", LogType.Error);
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"Registry error: {ex.Message}", LogType.Error);
            }
            return false;
        }
    }

    public class GhostProtocol : IModule
    {
        public string ModuleName => "Ghost Protocol";

        public bool Execute()
        {
            Logger.Instance.Header(ModuleName, "🛡️");
            Logger.Instance.Log("Performing system analysis...", LogType.System);

            var tweaks = new Dictionary<string, Action>
            {
                { "Windows Telemetry",     DisableTelemetry },
                { "Advertising Tracking",  DisableAds },
                { "Web Search in Start",   DisableBingSearch },
                { "Location Tracking",     DisableLocation },
                { "Activity History",      DisableActivityHistory },
                { "Feedback Notifications",DisableFeedback },
                { "Consumer Features",     DisableConsumerFeatures }
            };

            int completed = 0;

            foreach (var tweak in tweaks)
            {
                Logger.Instance.Log($"Processing: {tweak.Key}...", LogType.Info, "🔧");
                try
                {
                    tweak.Value.Invoke();
                    completed++;
                }
                catch (Exception ex)
                {
                    Logger.Instance.Log($"Failed: {tweak.Key}: {ex.Message}", LogType.Warning);
                }
            }

            Logger.Instance.Log($"Module finished. [{completed}/{tweaks.Count} successful]", LogType.Success, "✓");
            return completed > 0;
        }

        private void DisableTelemetry()
        {
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "MaxTelemetryAllowed", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "AllowTelemetry", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\DiagTrack", "Start", 4, RegistryValueKind.DWord);
        }

        private void DisableAds()
        {
            RegistryHandler.SetKey("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo", "Enabled", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SilentInstalledAppsEnabled", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SystemPaneSuggestionsEnabled", 0, RegistryValueKind.DWord);
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
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "OemPreInstalledAppsEnabled", 0, RegistryValueKind.DWord);
            RegistryHandler.SetKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "PreInstalledAppsEnabled", 0, RegistryValueKind.DWord);
        }
    }

    public class SculptorEngine : IModule
    {
        public string ModuleName => "Sculptor Engine";

        private readonly string[] _backgroundProcesses =
        {
            "OneDrive", "SkypeApp", "YourPhone", "MicrosoftEdgeUpdate",
            "XboxGameBar", "GameBar", "PhoneExperienceHost"
        };

        private readonly string[] _criticalProcesses =
        {
            "System", "csrss", "smss", "services", "lsass",
            "svchost", "dwm", "explorer", "winlogon", "wininit"
        };

        public bool Execute()
        {
            Logger.Instance.Header(ModuleName, "⚡");
            Logger.Instance.Log("Performing system analysis...", LogType.System);

            var (totalRAM, availableRAM, cpuUsage) = SystemAnalyzer.GetSystemMetrics();
            Logger.Instance.Progress($"Total RAM: {totalRAM / 1024 / 1024 / 1024}GB | Available: {availableRAM / 1024 / 1024}MB");
            Logger.Instance.Progress($"CPU Usage: {cpuUsage:F1}% | Processes: {SystemAnalyzer.GetActiveProcessCount()}");

            Logger.Instance.Log("Initiating optimization sequence...", LogType.Info, "🔧");

            int processesOptimized = PerformProcessOptimization();
            OptimizeSystemSettings();
            ConfigureHighPerformance();

            Logger.Instance.Log($"Module finished. Processes optimized: {processesOptimized}", LogType.Success, "✓");
            Logger.Instance.Log("Note: A restart may be required for some settings to take effect.", LogType.Warning, "⚠️");
            return true;
        }

        private int PerformProcessOptimization()
        {
            Logger.Instance.Log("Analyzing background processes...", LogType.Info, "🔍");
            int optimized = 0;

            Process[] allProcesses = Process.GetProcesses();

            foreach (var procName in _backgroundProcesses)
            {
                foreach (var p in allProcesses.Where(x => x.ProcessName.Equals(procName, StringComparison.OrdinalIgnoreCase)))
                {
                    try
                    {
                        using (p)
                        {
                            if (!p.HasExited)
                            {
                                p.PriorityClass = ProcessPriorityClass.Idle;
                                optimized++;
                                Logger.Instance.Progress($"Optimized: {p.ProcessName} (PID: {p.Id})");
                            }
                        }
                    }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                }
            }

            foreach (var p in allProcesses)
                try { p.Dispose(); } catch { }

            if (optimized == 0)
                Logger.Instance.Log("No target background processes found.", LogType.Info);

            return optimized;
        }

        private void OptimizeSystemSettings()
        {
            Logger.Instance.Log("Configuring system settings...", LogType.Info, "💾");
            try
            {
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "LargeSystemCache", 0, RegistryValueKind.DWord);
                Logger.Instance.Progress("System settings applied.");
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"Settings failed: {ex.Message}", LogType.Warning);
            }
        }

        private void ConfigureHighPerformance()
        {
            Logger.Instance.Log("Configuring high performance power plan...", LogType.Info, "⚡");
            try
            {
                var listPsi = new ProcessStartInfo
                {
                    FileName = "powercfg.exe",
                    Arguments = "/list",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };

                string guid = null;
                using (var listProc = Process.Start(listPsi))
                {
                    string output = listProc.StandardOutput.ReadToEnd();
                    listProc.WaitForExit(5000);
                    foreach (var line in output.Split('\n'))
                    {
                        if (line.IndexOf("High performance", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            line.IndexOf("Yüksek performans", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            var parts = line.Split(':');
                            if (parts.Length > 1)
                            {
                                guid = parts[1].Trim().Split(' ')[0].Trim();
                                break;
                            }
                        }
                    }
                }

                if (string.IsNullOrEmpty(guid))
                {
                    Logger.Instance.Log("High Performance plan not found on this system.", LogType.Warning);
                    return;
                }

                var setPsi = new ProcessStartInfo
                {
                    FileName = "powercfg.exe",
                    Arguments = $"/setactive {guid}",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (var setProc = Process.Start(setPsi))
                {
                    setProc.WaitForExit(5000);
                    if (setProc.ExitCode == 0)
                        Logger.Instance.Progress($"Power plan set to High Performance (GUID: {guid})");
                    else
                    {
                        string err = setProc.StandardError.ReadToEnd();
                        Logger.Instance.Log($"Power plan change failed: {err}", LogType.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"Power configuration failed: {ex.Message}", LogType.Warning);
            }
        }
    }

    public class NetworkBooster : IModule
    {
        public string ModuleName => "Net Booster";

        public bool Execute()
        {
            Logger.Instance.Header(ModuleName, "🚀");
            Logger.Instance.Log("Analyzing network configuration...", LogType.System);

            DisplayNetworkInfo();

            Logger.Instance.Log("Applying TCP/IP optimizations...", LogType.Info, "🔧");

            int completed = 0;
            if (FlushDNSCache()) completed++;
            completed += ResetNetworkStack();
            if (OptimizeTCPParameters()) completed++;
            if (ConfigureDNSCache()) completed++;

            Logger.Instance.Log($"Module finished. [{completed} operations successful]", LogType.Success, "✓");
            Logger.Instance.Log("A system restart is required for Winsock/TCP stack resets to take effect.", LogType.Warning, "⚠️");
            return completed > 0;
        }

        private void DisplayNetworkInfo()
        {
            try
            {
                var activeInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(ni => ni.OperationalStatus == OperationalStatus.Up &&
                                 ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .ToList();

                if (!activeInterfaces.Any())
                {
                    Logger.Instance.Log("No active network interfaces found.", LogType.Warning);
                    return;
                }

                foreach (var ni in activeInterfaces)
                    Logger.Instance.Progress($"Interface: {ni.Name} | Speed: {ni.Speed / 1_000_000.0:F0} Mbps | Type: {ni.NetworkInterfaceType}");
            }
            catch { }
        }

        private bool FlushDNSCache()
        {
            if (RunCommand("ipconfig", "/flushdns"))
            {
                Logger.Instance.Progress("DNS cache flushed.");
                return true;
            }
            return false;
        }

        private int ResetNetworkStack()
        {
            Logger.Instance.Log("Resetting network stack components...", LogType.Info);
            int count = 0;

            if (RunCommand("netsh", "winsock reset"))
            {
                Logger.Instance.Progress("Winsock catalog reset successful.");
                count++;
            }

            if (RunCommand("netsh", "int ip reset"))
            {
                Logger.Instance.Progress("TCP/IP stack reset successful.");
                count++;
            }

            return count;
        }

        private bool OptimizeTCPParameters()
        {
            Logger.Instance.Log("Configuring TCP parameters...", LogType.Info, "⚙️");
            try
            {
                RunCommand("netsh", "int tcp set global autotuninglevel=normal");

                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Tcp1323Opts", 1, RegistryValueKind.DWord);
                RegistryHandler.SetKey("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "NetworkThrottlingIndex", 10, RegistryValueKind.DWord);

                Logger.Instance.Progress("TCP/IP parameters applied.");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"TCP optimization warning: {ex.Message}", LogType.Warning);
                return false;
            }
        }

        private bool ConfigureDNSCache()
        {
            Logger.Instance.Log("Optimizing DNS cache settings...", LogType.Info, "🌐");
            try
            {
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "MaxCacheTtl", 3600, RegistryValueKind.DWord);
                RegistryHandler.SetKey("HKLM", @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters", "MaxNegativeCacheTtl", 300, RegistryValueKind.DWord);
                Logger.Instance.Progress("DNS cache settings applied.");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"DNS configuration warning: {ex.Message}", LogType.Warning);
                return false;
            }
        }

        private bool RunCommand(string cmd, string args)
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
                    string stdout = process.StandardOutput.ReadToEnd();
                    string stderr = process.StandardError.ReadToEnd();
                    process.WaitForExit(15000);
                    return process.ExitCode == 0;
                }
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"Command failed ({cmd} {args}): {ex.Message}", LogType.Error);
                return false;
            }
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                Logger.Instance.Log($"Unhandled exception: {e.ExceptionObject}", LogType.Critical);
                Console.ReadKey();
            };

            Console.OutputEncoding = Encoding.UTF8;
            Console.Title = "Cat-System | Professional Optimizer";

            if (!IsAdministrator())
            {
                Console.BackgroundColor = ConsoleColor.DarkRed;
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\n  ⚠️  ADMINISTRATOR PRIVILEGES REQUIRED! Please run as Administrator.\n");
                Console.ResetColor();
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            while (true)
            {
                try
                {
                    DrawUI();

                    Console.Write("Awaiting Command: ");
                    string input = Console.ReadLine()?.Trim();

                    IModule module = null;

                    switch (input)
                    {
                        case "1": module = new GhostProtocol();  break;
                        case "2": module = new SculptorEngine();  break;
                        case "3": module = new NetworkBooster();  break;
                        case "0": AnimateExit(); return;
                        default:
                            Logger.Instance.Log("Invalid selection. Please try again.", LogType.Warning, "⚠️");
                            Thread.Sleep(1200);
                            Console.Clear();
                            continue;
                    }

                    Console.Clear();

                    bool result = module.Execute();

                    if (!result)
                        Logger.Instance.Log("Module completed with errors or no changes were applied.", LogType.Warning);

                    Console.WriteLine("\n╔══════════════════════════════════════════════════════╗");
                    Console.WriteLine("║  Press ANY KEY to return to Main Menu               ║");
                    Console.WriteLine("╚══════════════════════════════════════════════════════╝");
                    Console.ReadKey();
                    Console.Clear();
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
            catch { return false; }
        }

        static void DrawUI()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
   ___      _     ____            _
  / __|__ _| |_  / ___| _   _ ___| |_ ___ _ __ ___
 | |  / _` | __| \___ \| | | / __| __/ _ \ '_ ` _ \
 | |_| (_| | |_   ___) | |_| \__ \ ||  __/ | | | | |
  \___\__,_|\__| |____/ \__, |___/\__\___|_| |_| |_|
                         |___/
");
            Console.WriteLine("══════════════════════════════════════════════════════════");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(" 🔰 Cat-System Core Loaded.");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($" 💻 System: {Environment.OSVersion.VersionString}");
            Console.WriteLine($" 👤 User: {Environment.UserName} | Admin Mode");
            Console.WriteLine($" 🛠️  Architect: Tc4dy | Version 2.1");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\nMAIN CONTROL PANEL");
            Console.ResetColor();
            Console.WriteLine("  [1] GHOST PROTOCOL  (Privacy & Telemetry Blocker)");
            Console.WriteLine("  [2] SCULPTOR ENGINE (CPU & Power Optimization)");
            Console.WriteLine("  [3] NET BOOSTER     (Network & DNS Configuration)");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("──────────────────────────────────────────────────────────");
            Console.ResetColor();
            Console.WriteLine("  [0] SHUTDOWN SYSTEM");
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

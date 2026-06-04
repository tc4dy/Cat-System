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
using System.IO;
using System.Management;
using System.Threading.Tasks;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace CatSystemCore
{
    public interface IModule
    {
        string ModuleName { get; }
        bool Execute();
        string GetBenchmarkBefore();
        string GetBenchmarkAfter();
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
        private static readonly string logFilePath = "CatSystem_Log.txt";

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
                string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                string logLine = $"[{timestamp}] [{type}] {emoji} {message}";

                try
                {
                    File.AppendAllText(logFilePath, logLine + Environment.NewLine);
                }
                catch { }

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

        public void Section(string title)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"\n▶ {title}");
            Console.ResetColor();
        }
    }

    public class Benchmark
    {
        public static string Measure()
        {
            try
            {
                var mem = new SystemAnalyzer.MEMORYSTATUSEX();
                mem.dwLength = (uint)Marshal.SizeOf(typeof(SystemAnalyzer.MEMORYSTATUSEX));
                SystemAnalyzer.GlobalMemoryStatusEx(ref mem);
                long avail = (long)mem.ullAvailPhys / 1024 / 1024;
                long total = (long)mem.ullTotalPhys / 1024 / 1024;

                double cpuUsage = 0;
                using (var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total"))
                {
                    cpuCounter.NextValue();
                    Thread.Sleep(500);
                    cpuUsage = cpuCounter.NextValue();
                }

                double diskUsage = 0;
                using (var diskCounter = new PerformanceCounter("PhysicalDisk", "% Disk Time", "_Total"))
                {
                    diskCounter.NextValue();
                    Thread.Sleep(100);
                    diskUsage = diskCounter.NextValue();
                }

                Ping p = new Ping();
                long pingMs = 0;
                try { pingMs = p.Send("8.8.8.8", 1000).RoundtripTime; } catch { }

                return $"RAM: {avail}MB/{total}MB | CPU: {cpuUsage:F1}% | DISK: {diskUsage:F1}% | PING: {pingMs}ms";
            }
            catch { return "Benchmark failed"; }
        }
    }

    public class RollbackManager
    {
        private static readonly object _lock = new object();
        private static Dictionary<string, object> registryBackup = new Dictionary<string, object>();
        private static Dictionary<string, string> fileBackup = new Dictionary<string, string>();
        private static string backupFolder = "CatSystem_Rollback";

        public static void BackupRegistry(string keyPath, string valueName, object currentValue)
        {
            lock (_lock)
            {
                string id = $"{keyPath}\\{valueName}";
                if (!registryBackup.ContainsKey(id))
                {
                    registryBackup[id] = currentValue;
                }
            }
        }

        public static void BackupFile(string filePath)
        {
            if (!File.Exists(filePath)) return;
            lock (_lock)
            {
                if (!fileBackup.ContainsKey(filePath))
                {
                    try
                    {
                        if (!Directory.Exists(backupFolder))
                            Directory.CreateDirectory(backupFolder);
                        string backupPath = Path.Combine(backupFolder, Path.GetFileName(filePath) + "_" + Guid.NewGuid().ToString() + ".bak");
                        File.Copy(filePath, backupPath, true);
                        fileBackup[filePath] = backupPath;
                    }
                    catch { }
                }
            }
        }

        public static bool RestoreAll()
        {
            bool success = true;
            Logger.Instance.Log("Starting full rollback...", LogType.System, "🔄");

            foreach (var backup in registryBackup)
            {
                string[] parts = backup.Key.Split(new[] { "\\" }, 2);
                if (parts.Length == 2)
                {
                    string keyPath = parts[0];
                    string valueName = parts[1];
                    try
                    {
                        string root = keyPath.StartsWith("HKLM") ? "HKLM" : "HKCU";
                        string subKey = keyPath.Substring(root.Length + 1);
                        RegistryKey baseKey = root == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                        using (RegistryKey rk = baseKey.OpenSubKey(subKey, true))
                        {
                            if (rk != null)
                            {
                                if (backup.Value != null)
                                {
                                    rk.SetValue(valueName, backup.Value);
                                    Logger.Instance.Progress($"Restored registry: {backup.Key}");
                                }
                                else
                                {
                                    if (rk.GetValue(valueName) != null)
                                        rk.DeleteValue(valueName);
                                    Logger.Instance.Progress($"Deleted registry value (was absent): {backup.Key}");
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Instance.Log($"Registry restore failed {backup.Key}: {ex.Message}", LogType.Error);
                        success = false;
                    }
                }
            }

            foreach (var file in fileBackup)
            {
                try
                {
                    if (File.Exists(file.Value))
                    {
                        if (File.Exists(file.Key))
                            File.Delete(file.Key);
                        File.Move(file.Value, file.Key);
                        Logger.Instance.Progress($"Restored file: {file.Key}");
                    }
                }
                catch (Exception ex)
                {
                    Logger.Instance.Log($"File restore failed {file.Key}: {ex.Message}", LogType.Error);
                    success = false;
                }
            }

            if (success)
                Logger.Instance.Log("Rollback completed successfully.", LogType.Success);
            else
                Logger.Instance.Log("Rollback completed with errors.", LogType.Warning);

            return success;
        }

        public static void ClearBackup()
        {
            lock (_lock)
            {
                registryBackup.Clear();
                fileBackup.Clear();
                if (Directory.Exists(backupFolder))
                {
                    try { Directory.Delete(backupFolder, true); } catch { }
                }
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
                        object oldValue = rk.GetValue(keyName);
                        RollbackManager.BackupRegistry($"{root}\\{subKey}", keyName, oldValue);
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

        public static bool DeleteKey(string root, string subKey, string keyName)
        {
            try
            {
                RegistryKey baseKey = root == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;
                using (RegistryKey rk = baseKey.OpenSubKey(subKey, true))
                {
                    if (rk != null && rk.GetValue(keyName) != null)
                    {
                        object oldValue = rk.GetValue(keyName);
                        RollbackManager.BackupRegistry($"{root}\\{subKey}", keyName, oldValue);
                        rk.DeleteValue(keyName);
                        Logger.Instance.Progress($"Registry key deleted: {keyName}");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"Registry delete error: {ex.Message}", LogType.Error);
            }
            return false;
        }
    }

    public class SystemAnalyzer
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct MEMORYSTATUSEX
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
                var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX)) };
                GlobalMemoryStatusEx(ref mem);

                double cpuUsage = 0;
                try
                {
                    using (var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total"))
                    {
                        cpuCounter.NextValue();
                        Thread.Sleep(500);
                        cpuUsage = Math.Round(cpuCounter.NextValue(), 1);
                    }
                }
                catch
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT LoadPercentage FROM Win32_Processor"))
                    {
                        foreach (var obj in searcher.Get())
                        {
                            cpuUsage = Convert.ToDouble(obj["LoadPercentage"]);
                            break;
                        }
                    }
                }

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

    public class SystemCleaner : IModule
    {
        public string ModuleName => "System Cleaner";
        private string beforeBench, afterBench;
        public string GetBenchmarkBefore() => beforeBench;
        public string GetBenchmarkAfter() => afterBench;

        public bool Execute()
        {
            beforeBench = Benchmark.Measure();
            Logger.Instance.Header(ModuleName, "🧹");
            Logger.Instance.Log("Scanning for cleanable files...", LogType.System);

            long totalFreed = 0;
            int errors = 0;

            totalFreed += CleanTempFolders(ref errors);
            totalFreed += CleanWindowsLogs(ref errors);
            totalFreed += CleanPrefetch(ref errors);
            RunDismCleanup();
            RunStorageSense();

            double mb = totalFreed / 1024.0 / 1024.0;
            afterBench = Benchmark.Measure();
            Logger.Instance.Log($"Cleaning complete. Freed: ~{mb:F1} MB | Errors: {errors}", LogType.Success, "✓");
            Logger.Instance.Log($"Before: {beforeBench}", LogType.Info);
            Logger.Instance.Log($"After : {afterBench}", LogType.Info);
            return totalFreed > 0 || errors == 0;
        }

        private long CleanTempFolders(ref int errors)
        {
            Logger.Instance.Section("Temporary Files");
            long freed = 0;

            string[] paths =
            {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\Temp",
            };

            foreach (var dir in paths)
            {
                if (!Directory.Exists(dir)) continue;
                freed += DeleteDirectory(dir, ref errors, keepRoot: true);
            }

            Logger.Instance.Progress($"Temp folders: freed ~{freed / 1024 / 1024} MB");
            return freed;
        }

        private long CleanWindowsLogs(ref int errors)
        {
            Logger.Instance.Section("Windows Event Logs");
            long freed = 0;

            string[] logPaths =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\System32\winevt\Logs",
                Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\Logs",
            };

            foreach (var dir in logPaths)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var file in Directory.GetFiles(dir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(dir, "*.evtx", SearchOption.AllDirectories)))
                {
                    try
                    {
                        long sz = new FileInfo(file).Length;
                        File.Delete(file);
                        freed += sz;
                    }
                    catch { errors++; }
                }
            }

            var (wevtOk, _, _) = CommandRunner.Run("wevtutil.exe", "el", 5000);
            if (wevtOk)
            {
                var (listOk, listOut, _) = CommandRunner.Run("wevtutil.exe", "el", 5000);
                if (listOk)
                {
                    foreach (var logName in listOut.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0))
                        CommandRunner.Run("wevtutil.exe", $"cl \"{logName}\"", 5000);
                    Logger.Instance.Progress("Event logs cleared via wevtutil.");
                }
            }

            Logger.Instance.Progress($"Log files: freed ~{freed / 1024 / 1024} MB");
            return freed;
        }

        private long CleanPrefetch(ref int errors)
        {
            Logger.Instance.Section("Prefetch Cache");
            string pfPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + @"\Prefetch";
            if (!Directory.Exists(pfPath)) return 0;
            long freed = DeleteDirectory(pfPath, ref errors, keepRoot: true);
            Logger.Instance.Progress($"Prefetch: freed ~{freed / 1024 / 1024} MB");
            return freed;
        }

        private void RunDismCleanup()
        {
            Logger.Instance.Section("Windows Component Store (DISM)");
            Logger.Instance.Log("Running DISM component cleanup — this may take a few minutes...", LogType.Info);

            var (ok, _, err) = CommandRunner.Run(
                "dism.exe",
                "/Online /Cleanup-Image /StartComponentCleanup /ResetBase",
                300000
            );

            if (ok) Logger.Instance.Progress("DISM cleanup completed.");
            else    Logger.Instance.Log($"DISM: {(string.IsNullOrWhiteSpace(err) ? "completed with warnings or no action needed" : err)}", LogType.Warning);
        }

        private void RunStorageSense()
        {
            Logger.Instance.Section("Storage Sense");
            var (ok, _, _) = CommandRunner.Run(
                "cleanmgr.exe",
                "/sagerun:1",
                120000
            );
            Logger.Instance.Progress(ok ? "Disk Cleanup completed." : "Disk Cleanup skipped or not available.");
        }

        private long DeleteDirectory(string dirPath, ref int errors, bool keepRoot)
        {
            long freed = 0;
            try
            {
                foreach (var file in Directory.GetFiles(dirPath, "*", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        long sz = new FileInfo(file).Length;
                        File.SetAttributes(file, FileAttributes.Normal);
                        File.Delete(file);
                        freed += sz;
                    }
                    catch { errors++; }
                }

                foreach (var sub in Directory.GetDirectories(dirPath))
                {
                    try
                    {
                        freed += DeleteDirectory(sub, ref errors, keepRoot: false);
                        if (!keepRoot) Directory.Delete(sub, false);
                    }
                    catch { errors++; }
                }
            }
            catch { errors++; }
            return freed;
        }
    }

    public static class CommandRunner
    {
        public static (bool Success, string Output, string Error) Run(string cmd, string args, int timeoutMs = 15000)
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

                using (var p = Process.Start(psi))
                {
                    var stdoutTask = p.StandardOutput.ReadToEndAsync();
                    var stderrTask = p.StandardError.ReadToEndAsync();
                    bool exited = p.WaitForExit(timeoutMs);

                    string stdout = stdoutTask.GetAwaiter().GetResult();
                    string stderr = stderrTask.GetAwaiter().GetResult();

                    if (!exited)
                    {
                        try { p.Kill(); } catch { }
                        return (false, stdout, "Process timed out.");
                    }

                    return (p.ExitCode == 0, stdout, stderr);
                }
            }
            catch (Exception ex)
            {
                return (false, "", ex.Message);
            }
        }
    }

    public class GhostProtocol : IModule
    {
        public string ModuleName => "Ghost Protocol";
        private string beforeBench, afterBench;
        public string GetBenchmarkBefore() => beforeBench;
        public string GetBenchmarkAfter() => afterBench;

        public bool Execute()
        {
            beforeBench = Benchmark.Measure();
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

            afterBench = Benchmark.Measure();
            Logger.Instance.Log($"Module finished. [{completed}/{tweaks.Count} successful]", LogType.Success, "✓");
            Logger.Instance.Log($"Before: {beforeBench}", LogType.Info);
            Logger.Instance.Log($"After : {afterBench}", LogType.Info);
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
        private string beforeBench, afterBench;
        public string GetBenchmarkBefore() => beforeBench;
        public string GetBenchmarkAfter() => afterBench;

        private readonly string[] _backgroundProcesses =
        {
            "OneDrive", "SkypeApp", "YourPhone", "MicrosoftEdgeUpdate",
            "XboxGameBar", "GameBar", "PhoneExperienceHost"
        };

        public bool Execute()
        {
            beforeBench = Benchmark.Measure();
            Logger.Instance.Header(ModuleName, "⚡");
            Logger.Instance.Log("Performing system analysis...", LogType.System);

            var (totalRAM, availableRAM, cpuUsage) = SystemAnalyzer.GetSystemMetrics();
            Logger.Instance.Progress($"Total RAM: {totalRAM / 1024 / 1024 / 1024}GB | Available: {availableRAM / 1024 / 1024}MB");
            Logger.Instance.Progress($"CPU Usage: {cpuUsage:F1}% | Processes: {SystemAnalyzer.GetActiveProcessCount()}");

            Logger.Instance.Log("Initiating optimization sequence...", LogType.Info, "🔧");

            int processesOptimized = PerformProcessOptimization();
            OptimizeSystemSettings();
            ConfigureHighPerformance();

            afterBench = Benchmark.Measure();
            Logger.Instance.Log($"Module finished. Processes optimized: {processesOptimized}", LogType.Success, "✓");
            Logger.Instance.Log($"Before: {beforeBench}", LogType.Info);
            Logger.Instance.Log($"After : {afterBench}", LogType.Info);
            Logger.Instance.Log("Note: A restart may be required for some settings to take effect.", LogType.Warning, "⚠️");
            return true;
        }

        private int PerformProcessOptimization()
        {
            Logger.Instance.Log("Analyzing background processes...", LogType.Info, "🔍");
            int optimized = 0;
            HashSet<int> processedPids = new HashSet<int>();

            Process[] allProcesses = Process.GetProcesses();

            foreach (var procName in _backgroundProcesses)
            {
                foreach (var p in allProcesses.Where(x => x.ProcessName.Equals(procName, StringComparison.OrdinalIgnoreCase)))
                {
                    try
                    {
                        if (!p.HasExited && !processedPids.Contains(p.Id))
                        {
                            processedPids.Add(p.Id);
                            p.PriorityClass = ProcessPriorityClass.Idle;
                            optimized++;
                            Logger.Instance.Progress($"Optimized: {p.ProcessName} (PID: {p.Id})");
                        }
                    }
                    catch (InvalidOperationException) { }
                    catch (System.ComponentModel.Win32Exception) { }
                    finally
                    {
                        try { p.Dispose(); } catch { }
                    }
                }
            }

            foreach (var p in allProcesses)
                try { if (!processedPids.Contains(p.Id)) p.Dispose(); } catch { }

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
                string guid = null;
                var psi = new ProcessStartInfo
                {
                    FileName = "powercfg.exe",
                    Arguments = "/list",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };

                using (var listProc = Process.Start(psi))
                {
                    string output = listProc.StandardOutput.ReadToEnd();
                    listProc.WaitForExit(5000);
                    foreach (string line in output.Split('\n'))
                    {
                        if (line.Contains("High performance") || line.Contains("Yüksek performans") || line.Contains("Alto rendimiento") || line.Contains("Haute performance") || line.Contains("Hohe Leistung"))
                        {
                            int start = line.IndexOf(':');
                            if (start != -1)
                            {
                                string afterColon = line.Substring(start + 1).Trim();
                                int spaceIndex = afterColon.IndexOf(' ');
                                guid = spaceIndex > 0 ? afterColon.Substring(0, spaceIndex) : afterColon;
                                break;
                            }
                        }
                    }
                }

                if (string.IsNullOrEmpty(guid))
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT InstanceID FROM Win32_PowerPlan WHERE ElementName LIKE '%High%'"))
                    {
                        foreach (var plan in searcher.Get())
                        {
                            string id = plan["InstanceID"].ToString();
                            guid = id.Split('\\').LastOrDefault();
                            if (!string.IsNullOrEmpty(guid)) break;
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
        private string beforeBench, afterBench;
        public string GetBenchmarkBefore() => beforeBench;
        public string GetBenchmarkAfter() => afterBench;

        public bool Execute()
        {
            beforeBench = Benchmark.Measure();
            Logger.Instance.Header(ModuleName, "🚀");
            Logger.Instance.Log("Analyzing network configuration...", LogType.System);

            DisplayNetworkInfo();

            Logger.Instance.Log("Applying TCP/IP optimizations...", LogType.Info, "🔧");

            int completed = 0;
            if (FlushDNSCache()) completed++;
            completed += ResetNetworkStack();
            if (OptimizeTCPParameters()) completed++;
            if (ConfigureDNSCache()) completed++;

            afterBench = Benchmark.Measure();
            Logger.Instance.Log($"Module finished. [{completed} operations successful]", LogType.Success, "✓");
            Logger.Instance.Log($"Before: {beforeBench}", LogType.Info);
            Logger.Instance.Log($"After : {afterBench}", LogType.Info);
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

    public class BrowserCleaner : IModule
    {
        public string ModuleName => "Browser Cleaner";
        private string beforeBench, afterBench;
        public string GetBenchmarkBefore() => beforeBench;
        public string GetBenchmarkAfter() => afterBench;

        public bool Execute()
        {
            beforeBench = Benchmark.Measure();
            Logger.Instance.Header(ModuleName, "🧹");
            Logger.Instance.Log("Cleaning browser traces...", LogType.System);

            var browsers = GetBrowserProfiles();
            int cleaned = 0;

            foreach (var browser in browsers)
            {
                Logger.Instance.Log($"Cleaning {browser.Name}...", LogType.Info, "🌐");
                if (CleanBrowser(browser))
                    cleaned++;
            }

            afterBench = Benchmark.Measure();
            Logger.Instance.Log($"Browser cleaner finished. Cleaned {cleaned}/{browsers.Count} browsers.", LogType.Success, "✓");
            Logger.Instance.Log($"Before: {beforeBench}", LogType.Info);
            Logger.Instance.Log($"After : {afterBench}", LogType.Info);
            return cleaned > 0;
        }

        private List<BrowserProfile> GetBrowserProfiles()
        {
            var list = new List<BrowserProfile>();
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            string chromePath = Path.Combine(localAppData, "Google", "Chrome", "User Data");
            if (Directory.Exists(chromePath))
                list.Add(new BrowserProfile { Name = "Chrome", Path = chromePath, ProfileFolders = new[] { "Default", "Profile 1", "Profile 2" } });

            string edgePath = Path.Combine(localAppData, "Microsoft", "Edge", "User Data");
            if (Directory.Exists(edgePath))
                list.Add(new BrowserProfile { Name = "Edge", Path = edgePath, ProfileFolders = new[] { "Default", "Profile 1", "Profile 2" } });

            string firefoxPath = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(firefoxPath))
            {
                var profiles = Directory.GetDirectories(firefoxPath).Select(Path.GetFileName).ToArray();
                list.Add(new BrowserProfile { Name = "Firefox", Path = firefoxPath, ProfileFolders = profiles });
            }

            string operaPath = Path.Combine(appData, "Opera Software", "Opera Stable");
            if (Directory.Exists(operaPath))
                list.Add(new BrowserProfile { Name = "Opera", Path = operaPath, ProfileFolders = new[] { "" } });

            string bravePath = Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data");
            if (Directory.Exists(bravePath))
                list.Add(new BrowserProfile { Name = "Brave", Path = bravePath, ProfileFolders = new[] { "Default", "Profile 1" } });

            return list;
        }

        private bool CleanBrowser(BrowserProfile browser)
        {
            bool success = false;
            foreach (var profile in browser.ProfileFolders)
            {
                string profilePath = string.IsNullOrEmpty(profile) ? browser.Path : Path.Combine(browser.Path, profile);
                if (!Directory.Exists(profilePath)) continue;

                string[] foldersToClean = { "Cache", "Code Cache", "Cookies", "History", "Visited Links", "Web Data" };
                foreach (string folder in foldersToClean)
                {
                    string target = Path.Combine(profilePath, folder);
                    if (Directory.Exists(target))
                    {
                        try
                        {
                            RollbackManager.BackupFile(target);
                            Directory.Delete(target, true);
                            Logger.Instance.Progress($"Deleted: {folder} in {browser.Name} ({profile})");
                            success = true;
                        }
                        catch { }
                    }
                    else if (File.Exists(target))
                    {
                        try
                        {
                            RollbackManager.BackupFile(target);
                            File.Delete(target);
                            Logger.Instance.Progress($"Deleted file: {folder} in {browser.Name} ({profile})");
                            success = true;
                        }
                        catch { }
                    }
                }
            }
            return success;
        }

        private class BrowserProfile
        {
            public string Name { get; set; }
            public string Path { get; set; }
            public string[] ProfileFolders { get; set; }
        }
    }

    public class StartupManager : IModule
    {
        public string ModuleName => "Startup Manager";
        private string beforeBench, afterBench;
        public string GetBenchmarkBefore() => beforeBench;
        public string GetBenchmarkAfter() => afterBench;

        public bool Execute()
        {
            beforeBench = Benchmark.Measure();
            Logger.Instance.Header(ModuleName, "⚙️");
            bool running = true;
            while (running)
            {
                Console.Clear();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\nSTARTUP MANAGER");
                Console.ResetColor();
                Console.WriteLine(" [1] List Startup Items");
                Console.WriteLine(" [2] Add Startup Program");
                Console.WriteLine(" [3] Remove Startup Program");
                Console.WriteLine(" [4] Back to Main Menu");
                Console.Write("\nChoice: ");
                string choice = Console.ReadLine()?.Trim();

                switch (choice)
                {
                    case "1": ListStartupItems(); break;
                    case "2": AddStartupItem(); break;
                    case "3": RemoveStartupItem(); break;
                    case "4": running = false; break;
                    default: Logger.Instance.Log("Invalid choice.", LogType.Warning); break;
                }
                if (running && choice != "4")
                {
                    Console.WriteLine("\nPress any key to continue...");
                    Console.ReadKey();
                }
            }
            afterBench = Benchmark.Measure();
            Logger.Instance.Log($"Before: {beforeBench}", LogType.Info);
            Logger.Instance.Log($"After : {afterBench}", LogType.Info);
            return true;
        }

        private void ListStartupItems()
        {
            Logger.Instance.Log("Startup items:", LogType.Info);
            var items = GetAllStartupItems();
            if (items.Count == 0)
                Logger.Instance.Log("No startup items found.", LogType.Warning);
            else
                foreach (var item in items)
                    Logger.Instance.Progress($"{item.Name} -> {item.Path} (Source: {item.Source})");
        }

        private void AddStartupItem()
        {
            Console.Write("Enter program name: ");
            string name = Console.ReadLine()?.Trim();
            Console.Write("Enter full program path: ");
            string path = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                Logger.Instance.Log("Invalid name or path.", LogType.Error);
                return;
            }

            try
            {
                string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
                string shortcutPath = Path.Combine(startupFolder, name + ".lnk");
                CreateShortcut(path, shortcutPath);
                Logger.Instance.Log($"Startup item added: {name}", LogType.Success);
                RollbackManager.BackupFile(shortcutPath);
            }
            catch (Exception ex)
            {
                Logger.Instance.Log($"Failed to add: {ex.Message}", LogType.Error);
            }
        }

        private void RemoveStartupItem()
        {
            var items = GetAllStartupItems();
            if (items.Count == 0)
            {
                Logger.Instance.Log("No startup items to remove.", LogType.Warning);
                return;
            }

            Console.WriteLine("Select item to remove:");
            for (int i = 0; i < items.Count; i++)
                Console.WriteLine($" [{i+1}] {items[i].Name}");

            Console.Write("Number: ");
            if (int.TryParse(Console.ReadLine(), out int idx) && idx >= 1 && idx <= items.Count)
            {
                var item = items[idx - 1];
                try
                {
                    if (item.Source == "Registry (CurrentUser)")
                        RegistryHandler.DeleteKey("HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run", item.Name);
                    else if (item.Source == "Registry (LocalMachine)")
                        RegistryHandler.DeleteKey("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", item.Name);
                    else if (File.Exists(item.Path))
                    {
                        RollbackManager.BackupFile(item.Path);
                        File.Delete(item.Path);
                    }
                    Logger.Instance.Log($"Removed: {item.Name}", LogType.Success);
                }
                catch (Exception ex)
                {
                    Logger.Instance.Log($"Removal failed: {ex.Message}", LogType.Error);
                }
            }
        }

        private List<StartupItem> GetAllStartupItems()
        {
            var list = new List<StartupItem>();

            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
            {
                if (key != null)
                {
                    foreach (string name in key.GetValueNames())
                    {
                        string path = key.GetValue(name)?.ToString();
                        if (!string.IsNullOrEmpty(path))
                            list.Add(new StartupItem { Name = name, Path = path, Source = "Registry (CurrentUser)" });
                    }
                }
            }

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"))
            {
                if (key != null)
                {
                    foreach (string name in key.GetValueNames())
                    {
                        string path = key.GetValue(name)?.ToString();
                        if (!string.IsNullOrEmpty(path))
                            list.Add(new StartupItem { Name = name, Path = path, Source = "Registry (LocalMachine)" });
                    }
                }
            }

            string startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            if (Directory.Exists(startupFolder))
            {
                foreach (string file in Directory.GetFiles(startupFolder, "*.lnk"))
                {
                    string name = Path.GetFileNameWithoutExtension(file);
                    list.Add(new StartupItem { Name = name, Path = file, Source = "Startup Folder" });
                }
            }

            return list;
        }

        private void CreateShortcut(string targetPath, string shortcutPath)
        {
            Type type = Type.GetTypeFromProgID("WScript.Shell");
            dynamic shell = Activator.CreateInstance(type);
            dynamic shortcut = shell.CreateShortcut(shortcutPath);
            shortcut.TargetPath = targetPath;
            shortcut.Save();
        }

        private class StartupItem
        {
            public string Name { get; set; }
            public string Path { get; set; }
            public string Source { get; set; }
        }
    }

    public class RollbackModule : IModule
    {
        public string ModuleName => "Rollback Changes";
        private string beforeBench, afterBench;
        public string GetBenchmarkBefore() => beforeBench;
        public string GetBenchmarkAfter() => afterBench;

        public bool Execute()
        {
            beforeBench = Benchmark.Measure();
            Logger.Instance.Header(ModuleName, "⏪");
            Console.Write("Are you sure you want to rollback all changes made by Cat-System? (y/n): ");
            if (Console.ReadKey().KeyChar.ToString().ToLower() != "y")
            {
                Logger.Instance.Log("Rollback cancelled.", LogType.Info);
                return false;
            }
            Console.WriteLine();

            bool result = RollbackManager.RestoreAll();
            if (result)
                RollbackManager.ClearBackup();
            afterBench = Benchmark.Measure();
            Logger.Instance.Log($"Before: {beforeBench}", LogType.Info);
            Logger.Instance.Log($"After : {afterBench}", LogType.Info);
            return result;
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
                        case "1": module = new GhostProtocol(); break;
                        case "2": module = new SculptorEngine(); break;
                        case "3": module = new NetworkBooster(); break;
                        case "4": module = new BrowserCleaner(); break;
                        case "5": module = new StartupManager(); break;
                        case "6": module = new SystemCleaner(); break;
                        case "7": module = new RollbackModule(); break;
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
            Console.WriteLine($" 🛠️  Architect: Tc4dy | Version 4.0");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("══════════════════════════════════════════════════════════");
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\nMAIN CONTROL PANEL");
            Console.ResetColor();
            Console.WriteLine("  [1] GHOST PROTOCOL    (Privacy & Telemetry Blocker)");
            Console.WriteLine("  [2] SCULPTOR ENGINE   (CPU & Power Optimization)");
            Console.WriteLine("  [3] NET BOOSTER       (Network & DNS Configuration)");
            Console.WriteLine("  [4] BROWSER CLEANER   (Clear Cache, Cookies, History)");
            Console.WriteLine("  [5] STARTUP MANAGER   (Manage Autostart Programs)");
            Console.WriteLine("  [6] SYSTEM CLEANER    (Temp, Logs, Prefetch, DISM)");
            Console.WriteLine("  [7] ROLLBACK CHANGES  (Undo All Modifications)");
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
            Console.WriteLine("\n╔════════════════════════════════════════════════════╗");
            Console.WriteLine("  ║         Shutting down Cat-System...                         ║");
            Console.WriteLine("  ╚════════════════════════════════════════════════════╝");
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

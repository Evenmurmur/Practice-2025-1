using System;
using System.Windows;
using System.Windows.Threading;
using System.Diagnostics;
using System.Management;
using System.Collections.ObjectModel;
using Microsoft.Win32;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Secdisp
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        private readonly DispatcherTimer timer;
        private readonly ObservableCollection<ProcessInfo> processes;
        private readonly List<ProcessInfo> allProcesses;
        private readonly HashSet<string> knownProcesses;
        private readonly Dictionary<string, string> processHashes;
        private Dictionary<string, PerformanceCounter> processCpuCounters;
        private bool isUpdatingProcesses;
        private DateTime lastProcessUpdate = DateTime.MinValue;
        private const int PROCESS_UPDATE_INTERVAL = 2000; // 2 секунды между обновлениями процессов
        private const int CPU_MEASUREMENT_INTERVAL = 1000; // 1 секунда для измерения CPU
        private string currentSearchText = string.Empty;

        public MainWindow()
        {
            InitializeComponent();
            
            processes = new ObservableCollection<ProcessInfo>();
            allProcesses = new List<ProcessInfo>();
            knownProcesses = new HashSet<string>();
            processHashes = new Dictionary<string, string>();
            processCpuCounters = new Dictionary<string, PerformanceCounter>();
            
            processesList.ItemsSource = processes;
            
            timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            timer.Tick += Timer_Tick;
            timer.Start();
            
            // Запускаем первичное обновление
            Task.Run(() => RefreshProcesses());
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            try
            {
                UpdateSystemMetrics();
                
                if (processesList.IsVisible && !isUpdatingProcesses && 
                    (DateTime.Now - lastProcessUpdate).TotalMilliseconds >= PROCESS_UPDATE_INTERVAL)
                {
                    Task.Run(() => RefreshProcesses());
                }
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => MessageBox.Show($"Ошибка обновления: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error));
            }
        }

        private void UpdateSystemMetrics()
        {
            try
            {
                // Обновляем общую загрузку CPU
                using (var cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total"))
                {
                    cpuCounter.NextValue(); // Первое значение всегда 0
                    Thread.Sleep(100); // Уменьшаем время ожидания
                    float cpuUsage = cpuCounter.NextValue();
                    Dispatcher.Invoke(() =>
                    {
                        cpuUsageText.Text = $"Загрузка CPU: {cpuUsage:F1}%";
                        cpuProgressBar.Value = cpuUsage;
                    });
                }

                // Обновляем использование памяти
                using (var memoryCounter = new PerformanceCounter("Memory", "Available MBytes"))
                {
                    float availableMemory = memoryCounter.NextValue();
                    float totalMemory = new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory / (1024 * 1024);
                    float usedMemory = totalMemory - availableMemory;
                    float memoryUsagePercent = (usedMemory / totalMemory) * 100;

                    Dispatcher.Invoke(() =>
                    {
                        memoryUsageText.Text = $"Использование памяти: {memoryUsagePercent:F1}%";
                        memoryProgressBar.Value = memoryUsagePercent;
                    });
                }
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => MessageBox.Show($"Ошибка обновления метрик: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error));
            }
        }

        private void ScanSecurity_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Проверка антивируса
                CheckAntivirusStatus();
                
                // Проверка брандмауэра
                CheckFirewallStatus();
                
                // Проверка обновлений Windows
                CheckWindowsUpdates();
                
                // Обновляем список процессов для отображения результатов проверки
                Task.Run(() => RefreshProcesses());
                
                MessageBox.Show("Проверка безопасности завершена", "Информация", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при проверке безопасности: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CheckAntivirusStatus()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct"))
                {
                    var antivirusProducts = searcher.Get();
                    if (antivirusProducts.Count == 0)
                    {
                        MessageBox.Show("Антивирус не обнаружен. Рекомендуется установить антивирусное ПО.", 
                            "Предупреждение", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось проверить статус антивируса: {ex.Message}", 
                    "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CheckFirewallStatus()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM FirewallProduct"))
                {
                    var firewallProducts = searcher.Get();
                    if (firewallProducts.Count == 0)
                    {
                        MessageBox.Show("Брандмауэр не обнаружен. Рекомендуется включить брандмауэр Windows.", 
                            "Предупреждение", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось проверить статус брандмауэра: {ex.Message}", 
                    "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CheckWindowsUpdates()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\CIMV2", "SELECT * FROM Win32_QuickFixEngineering"))
                {
                    var updates = searcher.Get();
                    if (updates.Count == 0)
                    {
                        MessageBox.Show("Не удалось получить информацию об обновлениях Windows. Рекомендуется проверить наличие обновлений вручную.", 
                            "Предупреждение", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка при проверке обновлений Windows: {ex.Message}", 
                    "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportData_Click(object sender, RoutedEventArgs e)
        {
            var saveFileDialog = new SaveFileDialog
            {
                Filter = "CSV файлы (*.csv)|*.csv",
                Title = "Экспорт данных"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    using (var writer = new StreamWriter(saveFileDialog.FileName))
                    {
                        writer.WriteLine("Метрика,Значение");
                        writer.WriteLine($"CPU Usage,{cpuProgressBar.Value}%");
                        writer.WriteLine($"Memory Usage,{memoryProgressBar.Value}%");
                        
                        writer.WriteLine("\nПроцессы:");
                        writer.WriteLine("Имя,ID,Память (МБ),CPU (%),Путь,Уровень риска,Описание");
                        foreach (var process in processes)
                        {
                            writer.WriteLine($"{process.Name},{process.Id},{process.MemoryMB},{process.CpuUsage},{process.Path},{process.SecurityLevel},{process.SecurityDescription}");
                        }
                    }
                    MessageBox.Show("Данные успешно экспортированы", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Ошибка при экспорте данных: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void UpdateInterval_Click(object sender, RoutedEventArgs e)
        {
            var input = Microsoft.VisualBasic.Interaction.InputBox(
                "Введите интервал обновления в секундах (1-60):",
                "Интервал обновления",
                timer.Interval.TotalSeconds.ToString());

            if (double.TryParse(input, out double seconds) && seconds >= 1 && seconds <= 60)
            {
                timer.Interval = TimeSpan.FromSeconds(seconds);
                MessageBox.Show($"Интервал обновления установлен на {seconds} секунд", "Настройки", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("Неверное значение. Введите число от 1 до 60.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void RefreshProcesses_Click(object sender, RoutedEventArgs e)
        {
            if (!isUpdatingProcesses)
            {
                Task.Run(() => RefreshProcesses());
            }
        }

        private void ProcessSearch_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            if (processSearchBox == null) return;
            currentSearchText = processSearchBox.Text?.ToLower() ?? string.Empty;
            RefreshProcesses();
        }

        private void RefreshProcesses()
        {
            if (isUpdatingProcesses || processes == null) return;

            try
            {
                isUpdatingProcesses = true;
                var newProcesses = new List<ProcessInfo>();
                var processList = Process.GetProcesses();

                if (processList == null) return;

                Parallel.ForEach(processList, process =>
                {
                    if (process == null) return;

                    try
                    {
                        if (process.HasExited) return;

                        var processInfo = new ProcessInfo
                        {
                            Name = process.ProcessName ?? "Unknown",
                            Id = process.Id,
                            MemoryMB = Math.Round(process.WorkingSet64 / 1024.0 / 1024.0, 2),
                            Path = GetProcessPath(process)
                        };

                        try
                        {
                            processInfo.CpuUsage = GetProcessCpuUsage(process);
                        }
                        catch
                        {
                            processInfo.CpuUsage = 0;
                        }

                        try
                        {
                            var securityAnalysis = AnalyzeProcessSecurity(process, processInfo.Path);
                            processInfo.SecurityLevel = securityAnalysis.Level ?? "Неизвестно";
                            processInfo.SecurityDescription = securityAnalysis.Description ?? "Нет описания";
                        }
                        catch
                        {
                            processInfo.SecurityLevel = "Неизвестно";
                            processInfo.SecurityDescription = "Не удалось проанализировать процесс";
                        }

                        lock (newProcesses)
                        {
                            newProcesses.Add(processInfo);
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Ошибка при обработке процесса {process?.ProcessName}: {ex.Message}");
                    }
                    finally
                    {
                        try { process?.Dispose(); } catch { }
                    }
                });

                Dispatcher.Invoke(() =>
                {
                    try
                    {
                        if (processes == null) return;
                        processes.Clear();
                        foreach (var process in newProcesses.Where(p => p != null && (string.IsNullOrEmpty(currentSearchText) ||
                               (p.Name?.ToLower().Contains(currentSearchText) ?? false) ||
                               p.Id.ToString().Contains(currentSearchText))))
                        {
                            processes.Add(process);
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Ошибка при обновлении списка процессов: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                });

                lastProcessUpdate = DateTime.Now;
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    MessageBox.Show($"Критическая ошибка при обновлении процессов: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                });
            }
            finally
            {
                isUpdatingProcesses = false;
            }
        }

        private float GetProcessCpuUsage(Process process)
        {
            if (process == null || process.HasExited || string.IsNullOrEmpty(process.ProcessName))
                return 0;

            try
            {
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfProc_Process WHERE IDProcess = {process.Id}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return Convert.ToSingle(obj["PercentProcessorTime"]) / Environment.ProcessorCount;
                    }
                }
            }
            catch
            {
                // Если не удалось получить CPU через WMI, возвращаем 0
                return 0;
            }
            return 0;
        }

        private string GetProcessPath(Process process)
        {
            if (process == null || process.HasExited) return "Нет доступа";

            try
            {
                bool isWow64;
                if (IsWow64Process(process.Handle, out isWow64))
                {
                    // Если процесс 32-битный, используем WMI
                    if (isWow64)
                    {
                        using (var searcher = new ManagementObjectSearcher(
                            $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {process.Id}"))
                        {
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                return obj["ExecutablePath"]?.ToString() ?? "Нет доступа";
                            }
                        }
                    }
                    else
                    {
                        // Для 64-битных процессов используем прямой доступ
                        if (process.MainModule != null)
                        {
                            return process.MainModule.FileName ?? "Нет доступа";
                        }
                    }
                }

                // Если не удалось определить разрядность или получить путь
                using (var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {process.Id}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["ExecutablePath"]?.ToString() ?? "Нет доступа";
                    }
                }

                return "Нет доступа";
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка при получении пути процесса {process.ProcessName}: {ex.Message}");
                return "Нет доступа";
            }
        }

        private (string Level, string Description) AnalyzeProcessSecurity(Process process, string processPath)
        {
            var riskLevel = "Низкий";
            var description = new StringBuilder();

            try
            {
                // Проверка 1: Неизвестный процесс
                if (!knownProcesses.Contains(process.ProcessName))
                {
                    riskLevel = "Средний";
                    description.AppendLine("Неизвестный процесс");
                }

                // Проверка 2: Высокое использование CPU
                if (process.TotalProcessorTime.TotalMilliseconds > 1000)
                {
                    riskLevel = "Средний";
                    description.AppendLine("Высокое использование CPU");
                }

                // Проверка 3: Подозрительное расположение
                if (processPath != "Нет доступа")
                {
                    var suspiciousLocations = new[]
                    {
                        @"\Temp\",
                        @"\AppData\",
                        @"\Windows\Temp\"
                    };

                    if (suspiciousLocations.Any(loc => processPath.Contains(loc)))
                    {
                        riskLevel = "Высокий";
                        description.AppendLine("Процесс запущен из временной директории");
                    }
                }

                // Проверка 4: Изменение хеша файла
                if (processPath != "Нет доступа" && File.Exists(processPath))
                {
                    var currentHash = CalculateFileHash(processPath);
                    if (processHashes.ContainsKey(processPath))
                    {
                        if (processHashes[processPath] != currentHash)
                        {
                            riskLevel = "Высокий";
                            description.AppendLine("Файл процесса был изменен");
                        }
                    }
                    else
                    {
                        processHashes[processPath] = currentHash;
                    }
                }

                // Проверка 5: Подозрительные права доступа
                try
                {
                    var processSecurity = process.StartInfo?.UseShellExecute == true;
                    if (processSecurity)
                    {
                        riskLevel = "Средний";
                        description.AppendLine("Процесс имеет повышенные права доступа");
                    }
                }
                catch { }

                // Проверка 6: Необычное поведение
                if (process.Threads.Count > 10)
                {
                    riskLevel = "Средний";
                    description.AppendLine("Большое количество потоков");
                }

                // Добавляем процесс в список известных
                knownProcesses.Add(process.ProcessName);
            }
            catch
            {
                riskLevel = "Неизвестно";
                description.AppendLine("Не удалось проанализировать процесс");
            }

            return (riskLevel, description.ToString());
        }

        private string CalculateFileHash(string filePath)
        {
            using (var md5 = MD5.Create())
            using (var stream = File.OpenRead(filePath))
            {
                var hash = md5.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);
            
            // Освобождаем ресурсы
            if (processCpuCounters != null)
            {
                foreach (var counter in processCpuCounters.Values)
                {
                    try
                    {
                        counter?.Dispose();
                    }
                    catch { }
                }
                processCpuCounters.Clear();
            }
        }
    }

    public class SecurityIssue
    {
        public string Level { get; set; }
        public string Description { get; set; }
        public string Recommendation { get; set; }
    }

    public class ProcessInfo
    {
        public string Name { get; set; }
        public int Id { get; set; }
        public double MemoryMB { get; set; }
        public double CpuUsage { get; set; }
        public string Path { get; set; }
        public string SecurityLevel { get; set; }
        public string SecurityDescription { get; set; }
    }
}

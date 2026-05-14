namespace OrkunPAM.Installer;

/// <summary>
/// Console output formatting helpers for the installer UI.
/// </summary>
public static class ConsoleHelper
{
    public static void WriteHeader(string text)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    public static void WriteStep(string text)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.Write("[*] ");
        Console.ResetColor();
        Console.WriteLine(text);
    }

    public static void WriteSuccess(string text)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write("[+] ");
        Console.ResetColor();
        Console.WriteLine(text);
    }

    public static void WriteError(string text)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Write("[-] ");
        Console.ResetColor();
        Console.WriteLine(text);
    }

    public static void WriteWarning(string text)
    {
        Console.ForegroundColor = ConsoleColor.DarkYellow;
        Console.Write("[!] ");
        Console.ResetColor();
        Console.WriteLine(text);
    }

    public static void WriteInfo(string text)
    {
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"    {text}");
        Console.ResetColor();
    }

    public static void WriteSeparator()
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine(new string('=', 70));
        Console.ResetColor();
    }

    /// <summary>
    /// Prompts for input with a default value.
    /// </summary>
    public static string Prompt(string label, string defaultValue = "")
    {
        Console.ForegroundColor = ConsoleColor.White;
        if (!string.IsNullOrEmpty(defaultValue))
            Console.Write($"  {label} [{defaultValue}]: ");
        else
            Console.Write($"  {label}: ");
        Console.ResetColor();

        var input = Console.ReadLine()?.Trim();
        return string.IsNullOrEmpty(input) ? defaultValue : input;
    }

    /// <summary>
    /// Prompts for a password (masked input).
    /// </summary>
    public static string PromptPassword(string label)
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"  {label}: ");
        Console.ResetColor();

        var password = string.Empty;
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                password = password[..^1];
                Console.Write("\b \b");
            }
            else if (!char.IsControl(key.KeyChar))
            {
                password += key.KeyChar;
                Console.Write("*");
            }
        }

        return password;
    }

    /// <summary>
    /// Prompts for Y/N confirmation.
    /// </summary>
    public static bool Confirm(string label, bool defaultYes = true)
    {
        var hint = defaultYes ? "Y/n" : "y/N";
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"  {label} [{hint}]: ");
        Console.ResetColor();

        var input = Console.ReadLine()?.Trim().ToUpperInvariant();
        if (string.IsNullOrEmpty(input)) return defaultYes;
        return input == "Y" || input == "YES";
    }

    /// <summary>
    /// Prompts for a boolean toggle selection (checkbox style).
    /// </summary>
    public static bool PromptToggle(string label, bool defaultValue = true)
    {
        var state = defaultValue ? "ON" : "OFF";
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($"  [{(defaultValue ? "X" : " ")}] {label} (Enter to toggle, Space to confirm) [{state}]: ");
        Console.ResetColor();

        var input = Console.ReadLine()?.Trim().ToUpperInvariant();
        if (string.IsNullOrEmpty(input)) return defaultValue;
        return input == "Y" || input == "YES" || input == "1" || input == "ON";
    }
}

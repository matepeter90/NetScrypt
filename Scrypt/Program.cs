namespace BlackFox.Cryptography.Scrypt
{
    using System;
    using System.IO;
    using BlackFox.Cryptography.Scrypt.ScryptCommandLine;
    using CommandLine;
    using CommandLine.Text;

    class Program
    {
        static void Main(string[] args)
        {
            string verb;
            var parsedArgs = ScryptCommandLineArgs.Parse(args, out verb);

            if (verb == "enc")
            {
                Encrypt(parsedArgs);
            }
            else if (verb == "dec")
            {
                Decrypt(parsedArgs);
            }
            else if (verb == "help")
            {
                Help(parsedArgs);
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        static void Help(ScryptCommandLineArgs parsedArgs)
        {
            var helpParams = parsedArgs.HelpVerb;
            var helpText = string.IsNullOrEmpty(helpParams.Verb)
                ? HelpText.AutoBuild(parsedArgs, _ => { }, true)
                : HelpText.AutoBuild(parsedArgs, helpParams.Verb);

            Console.WriteLine(helpText);
        }

        static void Decrypt(ScryptCommandLineArgs parsedArgs)
        {
            var encryptParams = parsedArgs.DecryptVerb;

            if (string.IsNullOrEmpty(encryptParams.InputFile) || string.IsNullOrEmpty(encryptParams.OutputFile))
            {
                Console.WriteLine(HelpText.AutoBuild(parsedArgs, "dec"));
                Environment.Exit(Parser.DefaultExitCodeFail);
            }

            using (var input = ConsoleUtils.OpenStreamOrExit(encryptParams.InputFile, FileMode.Open, FileAccess.Read, "Cannot open input file"))
            using (var output = ConsoleUtils.OpenStreamOrExit(encryptParams.OutputFile, FileMode.Create, FileAccess.ReadWrite, "Cannot open output file"))
            {
                var password = ConsoleUtils.ReadPassword("Please enter passphrase: ");

                Console.WriteLine();

                var encryption = new ScryptEncryption(password, encryptParams.MaxMemoryBytes,
                    encryptParams.MaxMemoryPercentage,
                    TimeSpan.FromSeconds(encryptParams.MaxTimeSeconds));

                encryption.Decrypt(input, output);
            }
        }

        static void Encrypt(ScryptCommandLineArgs parsedArgs)
        {
            var encryptParams = parsedArgs.EncryptVerb;

            if (string.IsNullOrEmpty(encryptParams.InputFile) || string.IsNullOrEmpty(encryptParams.OutputFile))
            {
                Console.WriteLine(HelpText.AutoBuild(parsedArgs, "enc"));
                Environment.Exit(Parser.DefaultExitCodeFail);
            }

            using (var input = ConsoleUtils.OpenStreamOrExit(encryptParams.InputFile, FileMode.Open, FileAccess.Read, "Cannot open input file"))
            using (var output = ConsoleUtils.OpenStreamOrExit(encryptParams.OutputFile, FileMode.Create, FileAccess.ReadWrite, "Cannot open output file"))
            {
                var password = ConsoleUtils.ReadPasswords("Please enter passphrase: ", "Please confirm passphrase: ");

                Console.WriteLine();

                var encryption = new ScryptEncryption(password, encryptParams.MaxMemoryBytes,
                    encryptParams.MaxMemoryPercentage,
                    TimeSpan.FromSeconds(encryptParams.MaxTimeSeconds));

                encryption.Encrypt(input, output);
            }
        }
    }
}
namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;
    using System.IO;
    using System.Security;
    using BlackFox.Cryptography.NetScrypt.Scrypt.ScryptCommandLine;

    class Program
    {
        static void Main(string[] args)
        {
            string verb;
            var parsedArgs = ScryptCommandLineArgs.Parse(args, out verb);

            if (verb == "enc")
            {
                var encryptParams = parsedArgs.EncryptVerb;

                Console.Write("Please enter passphrase: ");
                var password = ReadPassword();
                //TODO: Ask password twice

                Console.WriteLine();
                Console.WriteLine("Encrypting file...");

                var encryption = new ScryptEncryption(password, encryptParams.MaxMemoryBytes, encryptParams.MaxMemoryPercentage,
                    TimeSpan.FromSeconds(encryptParams.MaxTimeSeconds));

                using (var input = new FileStream(encryptParams.InputFile, FileMode.Open))
                using (var output = new FileStream(encryptParams.OutputFile, FileMode.Create))
                {
                    encryption.Encrypt(input, output);
                }

                Console.WriteLine("Done.");
                Console.ReadLine();
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        static SecureString ReadPassword()
        {
            while (Console.KeyAvailable)
            {
                Console.ReadKey(true);
            }

            var result = new SecureString();
            do
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }
                result.AppendChar(key.KeyChar);
            } while (true);

            return result;
        }
    }
}
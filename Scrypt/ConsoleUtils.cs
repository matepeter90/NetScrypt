namespace BlackFox.Cryptography.Scrypt
{
    using System;
    using System.IO;
    using System.Security;

    static class ConsoleUtils
    {
        public static FileStream OpenStreamOrExit(string path, FileMode fileMode, FileAccess fileAccess, string errorMessage)
        {
            try
            {
                return new FileStream(path, fileMode, fileAccess);
            }
            catch (Exception exception)
            {
                Console.WriteLine("{0}: {1}", errorMessage, path);
                Console.WriteLine(exception.Message);
                Environment.Exit(1);
                // ReSharper disable once HeuristicUnreachableCode
                return null;
            }
        }

        public static SecureString ReadPasswords(string prompt, string confirmPrompt)
        {
            SecureString password;
            bool success;
            do
            {
                password = ReadPassword(prompt);
                var password2 = ReadPassword(confirmPrompt);
                success = SecureStringUtils.Equals(password, password2);

                if (!success)
                {
                    Console.WriteLine("Passwords mismatch, please try again");
                }
            } while (!success);

            return password;
        }

        public static SecureString ReadPassword(string prompt)
        {
            Console.Write(prompt);
            var password = ReadPassword();
            Console.WriteLine();
            return password;
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
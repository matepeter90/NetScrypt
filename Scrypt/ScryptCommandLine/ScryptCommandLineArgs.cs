namespace BlackFox.Cryptography.NetScrypt.Scrypt.ScryptCommandLine
{
    using System;
    using CommandLine;
    using CommandLine.Text;

    class ScryptCommandLineArgs
    {
        [VerbOption("enc", HelpText = "Encrypts infile and writes the result to outfile if specified, or the standard output otherwise. "
                                      + "The user will be prompted to enter a passphrase (twice) to be used to generate a derived encryption key.")]
        public EncryptCommandLineArgs EncryptVerb { get; set; }

        [VerbOption("dec", HelpText = "Decrypts infile and writes the result to outfile if specified, or the standard output otherwise. "
                                      + "The user will be prompted to enter the passphrase used at encryption time to generate the derived "
                                      + "encryption key.")]
        public DecryptCommandLineArgs DecryptVerb { get; set; }

        [HelpVerbOption]
        public string GetUsage(string verb)
        {
            return HelpText.AutoBuild(this, verb);
        }

        public static ScryptCommandLineArgs Parse(string[] args, out string verb)
        {
            string verbForClosure = null;

            var arguments = new ScryptCommandLineArgs();
            if (!Parser.Default.ParseArguments(args, arguments,
                (foundVerb, subOptions) =>
                {
                    verbForClosure = foundVerb;
                }))
            {
                Console.WriteLine(HelpText.AutoBuild(arguments));
                Environment.Exit(Parser.DefaultExitCodeFail);
            }

            verb = verbForClosure;

            return arguments;
        }
    }
}
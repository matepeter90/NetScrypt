namespace BlackFox.Cryptography.Scrypt.ScryptCommandLine
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

        [VerbOption("help", HelpText = "Get help for the command line, follow by 'enc' or 'dec' to know their options.")]
        public HelpCommandLineArgs HelpVerb { get; set; }

        public ScryptCommandLineArgs()
        {
            EncryptVerb = new EncryptCommandLineArgs();
            DecryptVerb = new DecryptCommandLineArgs();
            HelpVerb = new HelpCommandLineArgs();
        }

        public static ScryptCommandLineArgs Parse(string[] args, out string verb)
        {
            if (args.Length == 0)
            {
                // Work around a bug in CommandLineParser that doesn't correctly support a custom 'help' verb.
                Console.WriteLine(HelpText.AutoBuild(new ScryptCommandLineArgs(), _ => { }, true));
                Environment.Exit(Parser.DefaultExitCodeFail);
            }

            string verbForClosure = null;

            var arguments = new ScryptCommandLineArgs();
            var parser = new Parser(settings => { settings.HelpWriter = null; });

            var parseSucceed = parser.ParseArguments(args, arguments,
                (foundVerb, subOptions) =>
                {
                    verbForClosure = foundVerb;
                });
            if (!parseSucceed)
            {
                Console.WriteLine(HelpText.AutoBuild(arguments, _ => { }, true));
                Environment.Exit(Parser.DefaultExitCodeFail);
            }

            verb = verbForClosure;

            return arguments;
        }
    }
}
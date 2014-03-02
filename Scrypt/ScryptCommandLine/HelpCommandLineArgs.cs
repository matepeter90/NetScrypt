namespace BlackFox.Cryptography.Scrypt.ScryptCommandLine
{
    using CommandLine;

    class HelpCommandLineArgs
    {
        [ValueOption(0)]
        public string Verb { get; set; }
    }
}
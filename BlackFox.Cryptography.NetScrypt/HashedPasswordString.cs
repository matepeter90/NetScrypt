namespace BlackFox.Cryptography.NetScrypt
{
    using System;
    using System.Text;

    public static class HashedPasswordString
    {
        public static string Create(SaltWithParameters saltWithParameters, string hashedPassword)
        {
            if (saltWithParameters == null) throw new ArgumentNullException("saltWithParameters");

            var builder = new StringBuilder();

            builder.Append("$scrypt$");
            builder.Append(saltWithParameters.Parameters.N);
            builder.Append("$");
            builder.Append(saltWithParameters.Parameters.R);
            builder.Append("$");
            builder.Append(saltWithParameters.Parameters.P);
            builder.Append("$");
            builder.Append(saltWithParameters.Parameters.HashLengthBytes);
            builder.Append("$");
            builder.Append(Convert.ToBase64String(saltWithParameters.Salt));
            builder.Append("$");
            builder.Append(hashedPassword);

            return builder.ToString();
        }

        public static bool TryParse(string hashedPasswordString, out SaltWithParameters saltWithParameters, out string hashedPassword)
        {
            var error = InternalTryParseSalt(hashedPasswordString, out saltWithParameters, out hashedPassword);
            return error == null;
        }

        public static void Parse(string hashedPasswordString, out SaltWithParameters saltWithParameters, out string hashedPassword)
        {
            var error = InternalTryParseSalt(hashedPasswordString, out saltWithParameters, out hashedPassword);
            if (error != null)
            {
                throw error;
            }
        }

        private static SaltParseException InternalTryParseSalt(string hashedPasswordString, out SaltWithParameters saltWithParameters,
            out string hashedPassword)
        {
            saltWithParameters = null;
            hashedPassword = null;

            ulong n;
            uint r, p, hashLengthBytes;

            var components = hashedPasswordString.Split('$');
            if (components.Length != 8)
                return new SaltParseException("Expected 8 dollar-sign ($) delimited salt components");
            if (components[0] != "" || components[1] != "scrypt")
                return new SaltParseException("Expected $scrypt$");
            if (!ulong.TryParse(components[2], out n))
                return new SaltParseException("Failed to parse N parameter");
            if (!uint.TryParse(components[3], out r))
                return new SaltParseException("Failed to parse r parameter");
            if (!uint.TryParse(components[4], out p))
                return new SaltParseException("Failed to parse p parameter");
            if (!uint.TryParse(components[5], out hashLengthBytes))
                return new SaltParseException("Failed to parse hashLengthBytes parameter");

            var saltBytes = Convert.FromBase64String(components[6]);
            var parameters = new ScryptParameters(n, r, p, hashLengthBytes, (uint)saltBytes.Length);
            saltWithParameters = new SaltWithParameters(saltBytes, parameters);

            hashedPassword = components[7];

            return null;
        }
    }
}
using System;
using System.Collections.Generic;
using System.Text;

namespace JoshuaCode.Cryptography
{
    public class CharacterSet
    {
        public char[] AllowedCharacters { get; }
        public int MinimumNumberRequired { get; }

        public CharacterSet(int minimumNumberRequired, char[] allowedCharacters)
        {
            if (minimumNumberRequired < 0)
            {
                throw new ArgumentOutOfRangeException($"{nameof(minimumNumberRequired)} must be greater than zero.");
            }
            if (allowedCharacters?.Length == 0)
            {
                throw new ArgumentOutOfRangeException($"{nameof(allowedCharacters)} must contain one or more characters.");
            }
            AllowedCharacters = allowedCharacters;
            MinimumNumberRequired = minimumNumberRequired;
        }

    }
}

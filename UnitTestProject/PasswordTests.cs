using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using JoshuaCode.Cryptography;
using System.Collections.Generic;
using System.Linq;

namespace UnitTestProject
{
    [TestClass]
    public class PasswordTests
    {
        [TestMethod]
        public void GeneratePassword_WithPasswordPolicy()
        {
            //arrange
            IEnumerable<CharacterSet> characterSets = new List<CharacterSet>()
            {
                new CharacterSet(1, "abcdefghijklmnopqrstuvwxyz".ToCharArray()),
                new CharacterSet(1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()),
                new CharacterSet(1, "1234567890".ToCharArray()),
                new CharacterSet(1, "*\\:,\"()<>+;/~".ToCharArray()),
            };

            PasswordPolicy passwordPolicy = new PasswordPolicy(characterSets, 14, 64);

            //act
            string password = Password.GeneratePassword(64, passwordPolicy);

            //assert
            Assert.IsTrue(password?.Length == 64);
            Assert.IsTrue(PasswordPolicy.IsPasswordCompliantWithPasswordPolicy(password, passwordPolicy));
        }
    }
}

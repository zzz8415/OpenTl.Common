using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace OpenTl.Common.UnitTests.Old.MTProto.Crypto
{
    internal class RsaServerKey
    {
        private readonly BigInteger _e;

        private readonly BigInteger _m;

        private string _fingerprint;

        public RsaServerKey(string fingerprint, BigInteger m, BigInteger e)
        {
            _fingerprint = fingerprint;
            _m = m;
            _e = e;
        }

        public byte[] Encrypt(byte[] data, int offset, int length)
        {
            using (var buffer = new MemoryStream(255))
            using (var writer = new BinaryWriter(buffer))
            {
                using (var sha1 = SHA1.Create())
                {
                    var hashsum = sha1.ComputeHash(data, offset, length);
                    writer.Write(hashsum);
                }

                buffer.Write(data, offset, length);
                if (length < 235)
                {
                    var padding = new byte[235 - length];
//                    new Random().NextBytes(padding);
                    buffer.Write(padding, 0, padding.Length);
                }

                var ciphertext = new BigInteger(1, buffer.ToArray()).ModPow(_e, _m).ToByteArrayUnsigned();

                if (ciphertext.Length == 256)
                {
                    return ciphertext;
                }

                {
                    var paddedCiphertext = new byte[256];
                    var padding = 256 - ciphertext.Length;
                    for (var i = 0; i < padding; i++)
                    {
                        paddedCiphertext[i] = 0;
                    }
                    ciphertext.CopyTo(paddedCiphertext, padding);
                    return paddedCiphertext;
                }
            }
        }
    }

    public class Rsa
    {
        private static readonly Dictionary<string, RsaServerKey> ServerKeys = new Dictionary<string, RsaServerKey>
                                                                              {
                                                                                  {
                                                                                      "523de07e9f4fde4d",
                                                                                      new RsaServerKey(
                                                                                          "523de07e9f4fde4d",
                                                                                          new BigInteger(
                                                                                              "15139472203035765582212819699376039739237231430878063495667795203229134980959324506614107122030408888925765072167986415265185361004591490736345898743490023603547950872793426919285195554897078495719060711729166132243640333584660392921258412595767310590865008962851391364739646962659581069648808963174358843784820200445578100191997004625297811317419569753018515657485951793008742176307195863614494307224727502073418469097656071836545428236253419337411340427010364863351130001006328014171326212488916317244724373594865620143031184196143080923682927050984628284249051543361912503019876492158261498002262083947738859676391",
                                                                                              10),
                                                                                          new BigInteger("65537", 10))
                                                                                  }
                                                                              };

        public static byte[] Encrypt(string fingerprint, byte[] data, int offset, int length)
        {
            var fingerprintLower = fingerprint.ToLower();
            if (!ServerKeys.ContainsKey(fingerprintLower))
            {
                return null;
            }

            var key = ServerKeys[fingerprintLower];

            return key.Encrypt(data, offset, length);
        }
    }
}
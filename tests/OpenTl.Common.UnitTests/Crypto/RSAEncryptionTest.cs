namespace OpenTl.Common.UnitTests.Crypto
{
    using System.Text;

    using OpenTl.Common.Crypto;

    using Xunit;

    public class RSAEncryptionTest
    {
        private const string PrivateKey = @"-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgEvGDDyx74XLxvNSze0HGlnaWwxTr5Ea0kv80Y7TIybil0vr0jGT
PvMxAVCHE/25PsiG1ZxfJ9+KG5eDq/SJ08stKtm7Fc3HYSKVeGRF0Qtc9KM4SCia
sIFIMDdFD59ppOS/3eCLVWfRuhRfKzm2lSwAUnb6lkuI0TQXlUieq5PdAgMBAAEC
gYAdf8q/zl37bqvTiscUohFGLdYIZIQTL6fzYUeMHPKwbsKMEhDQsAxvzQJAAXZs
7rNcifGbYQg65J99Swuktgu3vvNAaPc9hD2m2uh49/HBeeTtQ2+12Uc9dTEzE9ZS
BHk1a5LEAewFJY5PnsfpquGuKNXjpt2iA2HUmjg0d08gwQJBAJWVPZejX0uwn4IT
3uuts19vZDdyHqIDsV4BdY9U3YV3pvXTzeRVrO0A43z9O4G4cnCC+/frNAf4HOK2
8uKG/cUCQQCBrkyb7205YAK4DXMbTLqBOAj/isDQ1I7uoYoh/8+Rv1+TLFUHSDkP
wN1up/+VSuy1Wyo2INvQCRy0WULQ9Pc5AkBqxF10MN5CLk2MERbabd9MTTvg/4mx
5qThDnWU2uRK8b6wVH/vbN/DQxEdE7s3uimk+TlUGgPHdGdZw2/WFLhpAkBPnNv3
V3Psp17D863Y8rAFKIuNpnddPUFKiu2slcmupphcV/kTcWlmnHbUulqUIt1TMVam
yGFqRE3VAn+cnOcxAkAPIWKMe0MpL7nieUORnUFdh7PEIgVe2nMrXChfuU5E+dIX
4NBB1ZK8sljZ18/VYRBgF/kgVzG4KSZD/4dZvFBN
-----END RSA PRIVATE KEY-----";

        private const string PublicKey = @"-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgEvGDDyx74XLxvNSze0HGlnaWwxT
r5Ea0kv80Y7TIybil0vr0jGTPvMxAVCHE/25PsiG1ZxfJ9+KG5eDq/SJ08stKtm7
Fc3HYSKVeGRF0Qtc9KM4SCiasIFIMDdFD59ppOS/3eCLVWfRuhRfKzm2lSwAUnb6
lkuI0TQXlUieq5PdAgMBAAE=
-----END PUBLIC KEY-----";

        [Fact]
        public void SimpleTest()
        {
            var input = Encoding.UTF8.GetBytes("Perceived determine departure explained no forfeited");

            // Encrypt it
            var encryptedWithPublic = RSAHelper.RsaEncryptWithPublic(input, PublicKey);

            var encryptedWithPrivate = RSAHelper.RsaEncryptWithPrivate(input, PrivateKey);

            // Decrypt
            var output1 = RSAHelper.RsaDecryptWithPrivate(encryptedWithPublic, PrivateKey);

            var output2 = RSAHelper.RsaDecryptWithPublic(encryptedWithPrivate, PublicKey);

            Assert.Equal(output1, output2);
            Assert.Equal(output2, input);
        }
    }
}
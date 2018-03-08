using OpenTl.Common.Crypto;
using OpenTl.Schema;

using Xunit;

namespace OpenTl.Common.UnitTests
{
    using OpenTl.Common.Auth.Client;
    using OpenTl.Common.Auth.Server;

    using Org.BouncyCastle.Security;

    public class AuthTest
    {
        private const string PrivateKey = @"-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBx2z0wldA4Pqmew/sZrHqZNV1vfg951InYwNdD7vhAVrirvM1T
OaWrXGeE45ZEybdGBT9bpPqS9Im+HOKIdI+a7dr/uiXNDvoxXx8sJyMRCDmWdhJT
qBFVt///R8Phn99pFsdujidzMwXvZOdaw/NZjuv1ktzLYioEEgOBudGijpPxYXW0
eGfj+vAj/Bt2AqR6tcy3Gc72hcr0QiWWcqzrXIWM3Oe/OJmHA8qtSsyviVW0mF+o
w5ENY+17Wpf6dUI6JRcliPoPu7vURFQqX+NViPCFwj6ojNrKxGrPjViu3KY5pM+0
sf5M6jR1ipQKJ3gPxEPbToimrL9t6ErHcePNAgMBAAECggEAPcVYeVeOVDWLCRwC
y3cMPLr7KlYWR17MOtDE+ZJZFW73WhVgwFpyS3oin7JqAH//8vk92paza69IW+CH
9shmcQPC4SM5BvutOcQFwYqqN79inwMIBmMUpJDjTri8yVhXeUhmgtCVDqcL/Umd
S10sVdZ4pg87wwxLB1JOnL8XwT0nX+1Yag7tWN2MH/hjalin13JFwhR0207hw+dD
i6R2zjAxyXqa/8A0YyRH0vBqT9Jts3FoxKjemtt19E8NfDErdviQmob8bSrp0r1Q
w8nRUwAYLFPwDL9ZBSdetXx9J48Q0cteRmUhxRBBlc3JdgrUM0Sb9zQJJP8DNlj5
rmVlAQKBgQC8FKSa4qkwIy8D1yOuN7TnF82eVxeROMJlO+GEqzqq84wNfExhAbFA
QF3cMC+qVqXx4gxpWGIakszcg3q1Pvmc46uXjU6homb9dBno6l7gOc9DSvB/qav5
TubZkvgL95rFnyuknuS4uOo5mCXzENdjmSYG6xPaIVUSUFKD7Jaa3QKBgQCa+NdK
VgiIiZ/aO1w/Qmvn85TEywMkQVnIBasUYmuguKn2zMRy2gRssQ7bK3URAhSvF1sA
UkUK+MZ28w7JkSDfMfw5GYMv7wVDj+SVWN5Fkm1dE8uFy2r2XCd/OxAGVEV5fpgK
gATpWIr6CykE0s48KbedtN+HQnCWH6hEFIyFsQKBgDeQHaTIK1VWP5Bx4U+Zk27l
4E/TyNmVHBDOJOyNrVJNiuV9AA90cYnauh/PeHVpDbMspaAFhU32amEG0pxy00kf
FVU7YKxtjuF3iCQAATFawrlNjUkZtf176sUCHxdh+a5CPKFwc3+C2WdUZHmvUwJQ
fyRyFDZPvJMheY8RuNhdAoGAQuVb+ei9ckMGT+wD3ALOFahd9b00s/fJy8A2o2wA
zbYpGDI4MuPNuSWNJirSM+9UAmjwjWj2CNBuy3YMUhJlwDMRj4xlxtFE0m9Q2u8r
s5iLwPwEhNLUb1hEbHWQa0sBWnq9Ivs0I45nH5ylrkFZaTsQ2fDz9K1HcGZl+k1s
g2ECgYAulltLrCjZXfA4v/wpw+G0MzusWYxYgs8ttUWXZ3dEueIpXdhHG99rU20P
B4S3tPMw+UtnhB8DpLVnKriDhmb3RdAQDrKUuKI2cVtyTongDWZuqz4UHDD/uCAR
4OiGoTQMDZMPpiZmpulyWToZ35ygWmIJAJOcQ4B+KvU14Yd+vQ==
-----END RSA PRIVATE KEY-----";

        private const string PublicKey = @"-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBx2z0wldA4Pqmew/sZrHqZ
NV1vfg951InYwNdD7vhAVrirvM1TOaWrXGeE45ZEybdGBT9bpPqS9Im+HOKIdI+a
7dr/uiXNDvoxXx8sJyMRCDmWdhJTqBFVt///R8Phn99pFsdujidzMwXvZOdaw/NZ
juv1ktzLYioEEgOBudGijpPxYXW0eGfj+vAj/Bt2AqR6tcy3Gc72hcr0QiWWcqzr
XIWM3Oe/OJmHA8qtSsyviVW0mF+ow5ENY+17Wpf6dUI6JRcliPoPu7vURFQqX+NV
iPCFwj6ojNrKxGrPjViu3KY5pM+0sf5M6jR1ipQKJ3gPxEPbToimrL9t6ErHcePN
AgMBAAE=
-----END PUBLIC KEY-----";
        
        [Fact]
        public void SimpleTest()
        {
            var request =  Step1ClientHelper.GetRequest();
            var publicKeyFingerPrint = RSAHelper.GetFingerprint(PublicKey);
            var resPq = Step1ServerHelper.GetResponse(request.Nonce, publicKeyFingerPrint, out var p, out var q, out var serverNonce);

            var reqDhParams = Step2ClientHelper.GetRequest(resPq, PublicKey, out var newNonceFromClient);
            var serverDhParams = Step2ServerHelper.GetResponse(reqDhParams, PrivateKey, out var parameters, out var newNonceFromServer);
            
            Assert.Equal(newNonceFromClient, newNonceFromServer);
            
            var setClientDhParams =  Step3ClientHelper.GetRequest((TServerDHParamsOk) serverDhParams, newNonceFromClient, out var clientAgree, out var serverTime);
            var setClientDhParamsAnswer = Step3ServerHelper.GetResponse(setClientDhParams, newNonceFromClient, parameters, out var serverAgree, out var serverSalt);
            
            Assert.Equal(serverAgree.ToByteArray(), clientAgree);
        }
    }
}
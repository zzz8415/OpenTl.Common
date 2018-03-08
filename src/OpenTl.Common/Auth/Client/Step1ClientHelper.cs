namespace OpenTl.Common.Auth.Client
{
    using System;

    using OpenTl.Schema;

    public static class Step1ClientHelper
    {
        private static readonly Random Random = new Random();

        public static RequestReqPqMulty GetRequest()
        {
            var nonce = new byte[16];
            Random.NextBytes(nonce);
            
           return new RequestReqPqMulty {Nonce = nonce};
        }
    }
}
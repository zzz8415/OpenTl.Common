using System;
using OpenTl.Common.Auth;
using OpenTl.Common.Interfaces;
using OpenTl.Common.MtProto;
using OpenTl.Schema;
using OpenTl.Schema.Serialization;
using Xunit;

namespace OpenTl.Common.UnitTests
{
    public class MtProtoTest
    {
        private static readonly Random Random = new Random();

        public ISession session = GenerateSession();
        
        private ulong _messageId;
        public ulong MessageId => _messageId++;
        
        private int _seqNumber;
        public int SeqNumber => _seqNumber++;

        
        
        [Fact]
        public void EncriptionTest()
        {
            var user = new TUser
            {
                AccessHash = 11111,
                Id = 1
            };

            var data = Serializer.SerializeObject(user);

            MtProtoHelper.Encrypt(data, session, MessageId, SeqNumber);
        }

        private static ISession GenerateSession()
        {
            return new TestSession
            {
                AuthKey = GenerateAuthKey(),
                ServerTime = 1,
                SessionId = GenerateSessionId(),
                ServerSalt = GenerateSalt()
            };
        }
        private static ulong GenerateSessionId()
        {
            var data = new byte[8];
            Random.NextBytes(data);

            return BitConverter.ToUInt64(data, 0);
        }
        
        private static AuthKey GenerateAuthKey()
        {
            var keyData = new byte[597];
            Random.NextBytes(keyData);
            return  new AuthKey(keyData);
        }
        
        private static byte[] GenerateSalt()
        {
            var salt = new byte[8];
            Random.NextBytes(salt);

            return salt;
        }
      
    }
}
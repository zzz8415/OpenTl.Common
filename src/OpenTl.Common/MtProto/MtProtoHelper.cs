using System.IO;
using System.Linq;
using OpenTl.Common.Crypto;
using OpenTl.Common.Interfaces;
using Org.BouncyCastle.Crypto.Agreement.Kdf;

namespace OpenTl.Common.MtProto
{
//    public static class MtProtoHelper
//    {
//        public static byte[] Encrypt(byte[] packet, ISession session, ulong messageId, int seqNumber)
//        {
//            byte[] messsage;
//            using (var stream = new MemoryStream())
//            using (var binaryWriter = new BinaryWriter(stream))
//            {
//                binaryWriter.Write(session.ServerSalt);
//                binaryWriter.Write(session.SessionId);
//                binaryWriter.Write(messageId);
//                binaryWriter.Write(seqNumber);
//                binaryWriter.Write(packet.Length);
//                binaryWriter.Write(packet);
//
//                messsage = stream.ToArray();
//            }
//
//            var messageKey = SHA1Helper.ComputeHashsum(messsage).Take(16).ToArray();
//        }
//    }
}
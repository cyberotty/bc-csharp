using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
    public class CmsAuthEnvelopedGenerator : CmsEnvelopedGenerator
    {
        /// <summary>
        /// GCM/CCM parameter: Size of the 'number used once' (nonce)
        /// </summary>
        /// <remarks>
        /// A length of 12 octets is RECOMMENDED. (RFC5084)
        /// Other values are possible, but may require additional calculations
        /// by the cipher engine. This could possibly slow down
        /// the encryption process.
        /// </remarks>
        public int NonceSize { get; set; } = 12;

        /// <summary>
        /// GCM/CCM parameter: Size of the message authentication code (MAC)
        /// </summary>
        /// <remarks>
        /// The default size of the message authentication code is 12 bytes (RFC5084)
        /// However, the highest value (16) offers the highest possible security that
        /// the algorithm can provide. OpenSSL, for example, also uses the highest
        /// value as the default value.
        /// </remarks>
        public int MacSize { get; set; } = 16;

        /// <summary>
        /// Constructs an instance using the default values
        /// </summary>
        public CmsAuthEnvelopedGenerator()
            : base()
        {
        }

        /// <summary>
        /// Constructor allowing specific source of randomness
        /// </summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsAuthEnvelopedGenerator(SecureRandom random)
            : base(random)
        {
        }

        /// <summary>
        /// Called to generate a recipient info set. Each recipient info
        /// contains the content encryption key which is encrypted with
        /// the recipient's public key.
        /// </summary>
        /// <param name="encKey">Content encryption key</param>
        /// <returns></returns>
        protected internal virtual Asn1Set GenerateRecipientInfoSet(KeyParameter encKey)
        {
            Asn1EncodableVector recipientInfos =
                new Asn1EncodableVector(recipientInfoGenerators.Count);

            foreach (RecipientInfoGenerator rig in recipientInfoGenerators)
            {
                try
                {
                    recipientInfos.Add(rig.Generate(encKey, m_random));
                }
                catch (InvalidKeyException e)
                {
                    throw new CmsException("key inappropriate for algorithm.", e);
                }
                catch (GeneralSecurityException e)
                {
                    throw new CmsException("error making encrypted content.", e);
                }
            }

            Asn1Set recipientInfosSet = DerSet.FromVector(recipientInfos);

            return recipientInfosSet;
        }

        /// <summary>
        /// Encapsulates all algorithm parameters as an Ans1 encodable object.
        /// </summary>
        /// <param name="encryptionOid">Encryption algorithm oid</param>
        /// <param name="encKeyBytes">Encryption key bytes</param>
        /// <returns>Asn1Encodable object</returns>
        protected internal override Asn1Encodable GenerateAsn1Parameters(string encryptionOid, byte[] encKeyBytes)
        {
            if (encryptionOid == Aes128Gcm ||
                encryptionOid == Aes192Gcm ||
                encryptionOid == Aes256Gcm)
            {
                return new GcmParameters(SecureRandom.GetNextBytes(m_random, NonceSize), MacSize);
            }

            if (encryptionOid == Aes128Ccm ||
                encryptionOid == Aes192Ccm ||
                encryptionOid == Aes256Ccm)
            {
                return new CcmParameters(SecureRandom.GetNextBytes(m_random, NonceSize), MacSize);
            }

            throw new CmsException("Invalid content encryption algorithm: " + encryptionOid);
        }
    }
}

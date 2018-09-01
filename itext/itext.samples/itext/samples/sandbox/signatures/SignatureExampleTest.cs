

using System;
using System.Collections.Generic;
using System.IO;
using iText.IO.Image;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Samples;
using iText.Signatures;
using iText.Signatures.Testutils;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;

namespace itext.samples.sandbox.signatures
{
    public class SignatureExampleTest
    {
        public static readonly String DEST = NUnit.Framework.TestContext.CurrentContext.TestDirectory + "/test/resources/sandbox/signatures/signExample.pdf";

        public static readonly String SRC = NUnit.Framework.TestContext.CurrentContext.TestDirectory + "/../../resources/";

        public string certPath = SRC + "cert/signCertRsa01.p12";

        public char[] password = "testpass".ToCharArray();

        [Test]
        public void ManipulatePdf()
        {
            ElectronicSignatureInfoDTO signatureInfo = new ElectronicSignatureInfoDTO();
            signatureInfo.Bottom = 10;
            signatureInfo.Left = 10;
            signatureInfo.PageNumber = 1;
            SignDocumentSignature(DEST, signatureInfo);
        }

        public void SignDocumentSignature(string filePath, ElectronicSignatureInfoDTO signatureInfo)
        {
            if (signatureInfo != null)
            {
                //Maintain the same ratio as the height/width of the client's signature image
                const int signatureHeight = 25;
                const int signatureWidth = 150;

                string clientSignaturePath = SRC + "img/sign.jpg";
                string filePathSigned = string.Concat(filePath.Replace(".pdf", "_Signed.pdf"));

                try
                {
                    PdfReader pdfReader = new PdfReader(SRC + "pdfs/signExample.pdf");

                    PdfSigner pdfSigner = new PdfSigner(pdfReader, new FileStream(filePathSigned, FileMode.Create), new StampingProperties());

                    IExternalSignature pks = getPrivateKeySignature();
                    Org.BouncyCastle.X509.X509Certificate[] chain = getCertificateChain();

                    OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
                    OcspClientBouncyCastle ocspClient = new OcspClientBouncyCastle(ocspVerifier);
                    CrlClientOnline crlClient = new CrlClientOnline();

//                    TSAClientBouncyCastle tsa = new TSAClientBouncyCastle(GetTimeStampAuthority());

                    //Show image of the client's signature on the pdf
//                    SaveBase64AsImage(clientSignaturePath, agreementParameters.ClientSignature);
                    ImageData clientSignatureImage = ImageDataFactory.Create(clientSignaturePath);

                    pdfSigner.SetCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);
                    pdfSigner.SetFieldName("signature");

                    PdfSignatureAppearance signatureAppearance = pdfSigner.GetSignatureAppearance();
                    signatureAppearance.SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
                    signatureAppearance.SetReason("");
                    signatureAppearance.SetLocationCaption("");
                    signatureAppearance.SetSignatureGraphic(clientSignatureImage);
                    signatureAppearance.SetPageNumber(signatureInfo.PageNumber);
                    signatureAppearance.SetPageRect(new Rectangle(signatureInfo.Left, signatureInfo.Bottom,
                        signatureWidth, signatureHeight));

                    pdfSigner.SignDetached(pks, chain, (new List<ICrlClient>() {crlClient}), ocspClient, null /*should be tsa in the blog*/, 0,
                        PdfSigner.CryptoStandard.CMS);

                    // Replace the original agreement with the signed version
                    File.Delete(filePath);
                    File.Copy(filePathSigned, filePath);
                    File.Delete(filePathSigned);
                }
                catch
                {
                    throw;
                }
                finally
                {
                    //Remove signature images if it exists
                    if (!String.IsNullOrEmpty(clientSignaturePath) && File.Exists(clientSignaturePath))
                        File.Delete(clientSignaturePath);
                }
            }
        }

        private PrivateKeySignature getPrivateKeySignature()
        {
            ICipherParameters pk = Pkcs12FileHelper.ReadFirstKey(certPath, password, password);
            return new PrivateKeySignature(pk, DigestAlgorithms.SHA512);
        }

        private Org.BouncyCastle.X509.X509Certificate[] getCertificateChain()
        {
            return Pkcs12FileHelper.ReadFirstChain(certPath, password);

        }

    }

    public class ElectronicSignatureInfoDTO
    {
        public int PageNumber { get; set; }

        public float Left { get; set; }

        public float Bottom { get; set; }
    }

}

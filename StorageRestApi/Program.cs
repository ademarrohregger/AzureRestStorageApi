using System;
using System.Collections;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Web;

namespace StorageRestApi
{
    class Program
    {
        static void Main(string[] args)
        {
            string uri = string.Concat("http://", AzureConstants.Account, ".blob.core.windows.net/");
            BlobHelper helper = new BlobHelper("BlockBlob", uri);

            var conteudo = File.ReadAllBytes(@"C:\Penguins.jpg");
            
            helper.PutBlob("thblobpublico", "imagens2k13", conteudo);

            byte[] retorno = null;
            retorno = helper.GetBlob("thblobpublico", "imagens2k13");

            //helper.DeleteBlob("thblobpublico", "imagens2k13");

            Console.Read();
        }
    }

    class AzureConstants
    {
        //TODO:Configure aqui seu account
        public static string Account = "";

        //TODO:Configure aqui sua CHAVE DE ACESSO PRIMÁRIA
        public static string SecretKey = "";

        public static string SharedKeyAuthorizationScheme = "SharedKey";
    }

    class BlobHelper
    {
        public BlobHelper(string blobType, string blobEndPoint)
        {
            BlobType = blobType;
            BlobEndPoint = blobEndPoint;
        }

        public string BlobType { get; set; }
        public string BlobEndPoint { get; set; }

        private string CreateAuthorizationHeader(string canonicalizedstring)
        {
            string signature = string.Empty;
            using (
                System.Security.Cryptography.HMACSHA256 hmacSha256 =
                    new System.Security.Cryptography.HMACSHA256(Convert.FromBase64String(AzureConstants.SecretKey)))
            {
                Byte[] dataToHmac = System.Text.Encoding.UTF8.GetBytes(canonicalizedstring);
                signature = Convert.ToBase64String(hmacSha256.ComputeHash(dataToHmac));
            }

            string authorizationHeader = string.Format(CultureInfo.InvariantCulture, "{0} {1}:{2}",
                                                       AzureConstants.SharedKeyAuthorizationScheme,
                                                       AzureConstants.Account, signature);

            return authorizationHeader;
        }

        public string AuthorizationHeader(string method, DateTime now, HttpWebRequest request, string ifMatch = "", string md5 = "")
        {
            string MessageSignature;


            MessageSignature = String.Format("{0}\n\n\n{1}\n{5}\n\n\n\n{2}\n\n\n\n{3}{4}",
                method,
                (method == "GET" || method == "HEAD") ? String.Empty : request.ContentLength.ToString(),
                ifMatch,
                GetCanonicalizedHeaders(request),
                GetCanonicalizedResource(request.RequestUri, AzureConstants.Account),
                md5
                );

            byte[] SignatureBytes = System.Text.Encoding.UTF8.GetBytes(MessageSignature);
            System.Security.Cryptography.HMACSHA256 SHA256 = new System.Security.Cryptography.HMACSHA256(Convert.FromBase64String(AzureConstants.SecretKey));
            String AuthorizationHeader = "SharedKey " + AzureConstants.Account + ":" + Convert.ToBase64String(SHA256.ComputeHash(SignatureBytes));
            return AuthorizationHeader;
        }

        public string GetCanonicalizedResource(Uri address, string accountName)
        {
            StringBuilder str = new StringBuilder();
            StringBuilder builder = new StringBuilder("/");
            builder.Append(accountName);
            builder.Append(address.AbsolutePath);
            str.Append(builder.ToString());
            NameValueCollection values2 = new NameValueCollection();
            NameValueCollection values = HttpUtility.ParseQueryString(address.Query);
            foreach (string str2 in values.Keys)
            {
                ArrayList list = new ArrayList(values.GetValues(str2));
                list.Sort();
                StringBuilder builder2 = new StringBuilder();
                foreach (object obj2 in list)
                {
                    if (builder2.Length > 0)
                    {
                        builder2.Append(",");
                    }
                    builder2.Append(obj2.ToString());
                }
                values2.Add((str2 == null) ? str2 : str2.ToLowerInvariant(), builder2.ToString());
            }
            ArrayList list2 = new ArrayList(values2.AllKeys);
            list2.Sort();
            foreach (string str3 in list2)
            {
                StringBuilder builder3 = new StringBuilder(string.Empty);
                builder3.Append(str3);
                builder3.Append(":");
                builder3.Append(values2[str3]);
                str.Append("\n");
                str.Append(builder3.ToString());
            }
            return str.ToString();
        }

        public string GetCanonicalizedHeaders(HttpWebRequest request)
        {
            ArrayList headerNameList = new ArrayList();
            StringBuilder sb = new StringBuilder();
            foreach (string headerName in request.Headers.Keys)
            {
                if (headerName.ToLowerInvariant().StartsWith("x-ms-", StringComparison.Ordinal))
                {
                    headerNameList.Add(headerName.ToLowerInvariant());
                }
            }
            headerNameList.Sort();
            foreach (string headerName in headerNameList)
            {
                StringBuilder builder = new StringBuilder(headerName);
                string separator = ":";
                foreach (string headerValue in GetHeaderValues(request.Headers, headerName))
                {
                    string trimmedValue = headerValue.Replace("\r\n", String.Empty);
                    builder.Append(separator);
                    builder.Append(trimmedValue);
                    separator = ",";
                }
                sb.Append(builder.ToString());
                sb.Append("\n");
            }
            return sb.ToString();
        }

        public ArrayList GetHeaderValues(NameValueCollection headers, string headerName)
        {
            ArrayList list = new ArrayList();
            string[] values = headers.GetValues(headerName);
            if (values != null)
            {
                foreach (string str in values)
                {
                    list.Add(str.TrimStart(null));
                }
            }
            return list;
        }

        public async void PutBlob(String containerName, String blobName, byte[] blobContent, bool error = false)
        {
            String requestMethod = "PUT";
            String urlPath = String.Format("{0}/{1}", containerName, blobName);
            String storageServiceVersion = "2009-09-19";
            String dateInRfc1123Format = DateTime.UtcNow.ToString("R", CultureInfo.InvariantCulture);

            Int32 blobLength = blobContent.Length;

            String canonicalizedHeaders = String.Format(
                "x-ms-blob-type:{0}\nx-ms-date:{1}\nx-ms-version:{2}",
                BlobType,
                dateInRfc1123Format,
                storageServiceVersion);
            String canonicalizedResource = String.Format("/{0}/{1}", AzureConstants.Account, urlPath);
            String stringToSign = String.Format(
            "{0}\n\n\n{1}\n\n\n\n\n\n\n\n\n{2}\n{3}",
            requestMethod,
            blobLength,
            canonicalizedHeaders,
            canonicalizedResource);

            String authorizationHeader = CreateAuthorizationHeader(stringToSign);

            Uri uri = new Uri(BlobEndPoint + urlPath);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.Method = requestMethod;
            request.Headers["x-ms-blob-type"] = BlobType;
            request.Headers["x-ms-date"] = dateInRfc1123Format;
            request.Headers["x-ms-version"] = storageServiceVersion;
            request.Headers["Authorization"] = authorizationHeader;
            request.ContentLength = blobLength;

            try
            {
                using (Stream requestStream = await request.GetRequestStreamAsync())
                {
                    requestStream.Write(blobContent, 0, blobLength);
                }

                using (HttpWebResponse response = (HttpWebResponse)await request.GetResponseAsync())
                {
                    String ETag = response.Headers["ETag"];
                    System.Diagnostics.Debug.WriteLine(ETag);
                }
                error = false;
            }
            catch (WebException ex)
            {
                System.Diagnostics.Debug.WriteLine("An error occured. Status code:" + ((HttpWebResponse)ex.Response).StatusCode);
                System.Diagnostics.Debug.WriteLine("Error information:");
                error = true;
                using (Stream stream = ex.Response.GetResponseStream())
                {
                    using (StreamReader sr = new StreamReader(stream))
                    {
                        var s = sr.ReadToEnd();
                        System.Diagnostics.Debug.WriteLine(s);
                    }
                }
            }
        }

        public byte[] GetBlob(String containerName, String blobName)
        {
            String urlPath = String.Format("{0}/{1}", containerName, blobName);

            byte[] byteArray = null;
            DateTime now = DateTime.UtcNow;
            string uri = BlobEndPoint + urlPath;

            HttpWebRequest request = HttpWebRequest.Create(uri) as HttpWebRequest;
            request.Method = "GET";
            request.ContentLength = 0;
            request.Headers.Add("x-ms-date", now.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
            request.Headers.Add("x-ms-version", "2009-09-19");

            request.Headers.Add("Authorization", AuthorizationHeader("GET", now, request, "", ""));

            var bytes = default(byte[]);

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                String ETag = response.Headers["ETag"];
                System.Diagnostics.Debug.WriteLine(ETag);
                using (Stream stream = response.GetResponseStream())
                {
                    using (StreamReader sr = new StreamReader(stream))
                    {

                        using (var memstream = new MemoryStream())
                        {
                            sr.BaseStream.CopyTo(memstream);
                            bytes = memstream.ToArray();
                        }
                    }
                }
            }
            return bytes;
        }

        public bool DeleteBlob(String containerName, String blobName)
        {
            String requestMethod = "DELETE";

            String urlPath = String.Format("{0}/{1}", containerName, blobName);

            String storageServiceVersion = "2009-09-19";

            String dateInRfc1123Format = DateTime.UtcNow.ToString("R", CultureInfo.InvariantCulture);

            Int32 blobLength = 0; // blobContent.Length;

            String canonicalizedHeaders = String.Format(
                "x-ms-blob-type:{0}\nx-ms-date:{1}\nx-ms-version:{2}",
                BlobType,
                dateInRfc1123Format,
                storageServiceVersion);
            String canonicalizedResource = String.Format("/{0}/{1}", AzureConstants.Account, urlPath);
            String stringToSign = String.Format(
                "{0}\n\n\n{1}\n\n\n\n\n\n\n\n\n{2}\n{3}",
                requestMethod,
                blobLength,
                canonicalizedHeaders,
                canonicalizedResource);

            String authorizationHeader = CreateAuthorizationHeader(stringToSign);

            Uri uri = new Uri(BlobEndPoint + urlPath);
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.Method = requestMethod;
            request.Headers["x-ms-blob-type"] = BlobType;
            request.Headers["x-ms-date"] = dateInRfc1123Format;
            request.Headers["x-ms-version"] = storageServiceVersion;
            request.Headers["Authorization"] = authorizationHeader;
            request.ContentLength = blobLength;

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    String ETag = response.Headers["ETag"];
                    System.Diagnostics.Debug.WriteLine(ETag);
                    return true;
                }
            }
            catch (WebException ex)
            {
                System.Diagnostics.Debug.WriteLine("An error occured. Status code:" + ((HttpWebResponse)ex.Response).StatusCode);
                System.Diagnostics.Debug.WriteLine("Error information:");

                return false;
            }
        }
    }
}

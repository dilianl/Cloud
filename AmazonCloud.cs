// <copyright file="AmazonCloud.cs" company="Negometrix">
// Copyright © Negometrix. All rights reserved.
// </copyright>
// <summary>Contains AmazonCloud class.</summary>
namespace NX1.Clouds.CloudStorage.Amazon
{
    using System;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Globalization;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Model;
    using Model.Enums;

    /// <summary>
    /// Sample AWS4 signer demonstrating how to sign POST requests to Amazon S3
    /// using a policy.
    /// </summary>
    public class AmazonCloud : AmazonBase, ICloudStorage
    {
        /// <summary>
        /// Aws Access KeyId
        /// </summary>
        private static string accessKeyId = ConfigurationManager.AppSettings["AWSAccessKeyId"].ToString();

        /// <summary>
        /// Aws Secret Key
        /// </summary>
        private static string secretKey = ConfigurationManager.AppSettings["AWSSecretKey"].ToString();

        /// <summary>
        /// Aws Bucket Name
        /// </summary>
        private static string bucket = ConfigurationManager.AppSettings["AWSBucket"].ToString();

        /// <summary>
        /// Aws Region Name
        /// </summary>
        private static string region = ConfigurationManager.AppSettings["AWSRegion"].ToString();

        /// <summary>
        /// Aws Expire Time
        /// </summary>
        private static string expireTime = ConfigurationManager.AppSettings["AWSExpireTime"].ToString();

        /// <summary>
        /// Return container prefix
        /// </summary>
        private static string containerPrefix = ConfigurationManager.AppSettings["AWSContainerTemplate"].ToString();

        /// <summary>
        /// algorithm used to hash the canonical request that is supplied to the signature computation
        /// </summary>
        private static HashAlgorithm canonicalRequestHashAlgorithm = HashAlgorithm.Create("SHA-256");

        /// <summary>
        /// Format Algorithm For Policy
        /// </summary>
        /// <value>
        /// Format Algorithm For Policy
        /// </value>
        public static string FormatAlgorithmForPolicy
        {
            get { return "AWS4-HMAC-SHA256"; }
        }

        /// <summary>
        /// Get CloudStorageType
        /// </summary>
        /// <value>
        /// Return CloudStorageType
        /// </value>
        public CloudStorageType CloudType
        {
            get
            {
                return CloudStorageType.AmazonCloud;
            }
        }

        /// <summary>
        /// Format Credential String For Policy
        /// </summary>
        /// <returns>string</returns>
        public static string FormatCredentialStringForPolicy()
        {
            return "AKIAIOSFODNN7EXAMPLE/20130806/cn-north-1/s3/aws4_request";
        }

        /// <summary>
        /// dateTimeStamp
        /// </summary>
        /// <param name="timestamp">TimeStamp</param>
        /// <returns>string</returns>
        public static string FormatDateTimeForPolicy(DateTime timestamp)
        {
            return timestamp.ToString(BasicFormat, CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Computes an AWS4 signature for a request, ready for inclusion as an 'Authorization' header.
        /// </summary>
        /// <param name="headers">
        /// The request headers; 'Host' and 'X-Amz-Date' will be added to this set.
        /// </param>
        /// <param name="queryParameters">
        /// Any query parameters that will be added to the endpoint. The parameters should be specified in canonical format.
        /// </param>
        /// <param name="bodyHash">
        /// Precomputed SHA256 hash of the request body content; this value should also be set as the header 'X-Amz-Content-SHA256' for non-streaming uploads.
        /// </param>
        /// <param name="accessKey">
        /// The user's AWS Access Key.
        /// </param>
        /// <param name="secretKey">
        /// The user's AWS Secret Key.
        /// </param>
        /// <returns>
        /// The computed authorization string for the request. This value needs to be set as the header 'Authorization' on the subsequent HTTP request.
        /// </returns>
        public string ComputeSign(IDictionary<string, string> headers, string queryParameters, string bodyHash, string accessKey, string secretKey)
        {
            if (headers == null)
            {
                throw new ArgumentException("Headers is null");
            }

            // first get the date and time for the subsequent request, and convert to ISO 8601 format
            // for use in signature generation
            var requestDateTime = DateTime.UtcNow;
            var dateTimeStamp = requestDateTime.ToString(BasicFormat, CultureInfo.InvariantCulture);

            // update the headers with required 'x-amz-date' and 'host' values
            headers.Add(Date, dateTimeStamp);

            var hostHeader = this.EndpointUri.Host;
            if (!this.EndpointUri.IsDefaultPort)
            {
                hostHeader += ":" + this.EndpointUri.Port;
            }

            headers.Add("Host", hostHeader);

            // canonicalize the headers; we need the set of header names as well as the
            // names and values to go into the signature process
            var canonicalizedHeaderNames = CanonicalizeHeaderNames(headers);
            var canonicalizedHeaders = this.CanonicalizeHeaders(headers);

            // if any query string parameters have been supplied, canonicalize them
            // (note this sample assumes any required url encoding has been done already)
            var canonicalizedQueryParameters = string.Empty;
            if (!string.IsNullOrEmpty(queryParameters))
            {
                var paramDictionary = queryParameters.Split('&').Select(p => p.Split('='))
                                                     .ToDictionary(
                                                         nameval => nameval[0],
                                                                   nameval => nameval.Length > 1
                                                                        ? nameval[1] : string.Empty);

                var sb = new StringBuilder();
                var paramKeys = new List<string>(paramDictionary.Keys);
                paramKeys.Sort(StringComparer.Ordinal);
                foreach (var p in paramKeys)
                {
                    if (sb.Length > 0)
                    {
                        sb.Append("&");
                    }

                    sb.Append(string.Format(CultureInfo.CurrentCulture, "{0}={1}", p, paramDictionary[p]));
                }

                canonicalizedQueryParameters = sb.ToString();
            }

            // canonicalize the various components of the request
            var canonicalRequest = CanonicalizeRequest(this.EndpointUri, this.HttpMethod, canonicalizedQueryParameters, canonicalizedHeaderNames, canonicalizedHeaders, bodyHash);

            // generate a hash of the canonical request, to go into signature computation
            var canonicalRequestHashBytes
                = canonicalRequestHashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest));

            // construct the string to be signed
            var stringToSign = new StringBuilder();

            var dateStamp = requestDateTime.ToString(DateStringFormat, CultureInfo.InvariantCulture);
            var scope = string.Format(CultureInfo.CurrentCulture, "{0}/{1}/{2}/{3}", dateStamp, this.Region, this.Service, Terminator);
            stringToSign.Append(string.Format(CultureInfo.CurrentUICulture, "{0}-{1}\n{2}\n{3}\n", Scheme, Algorithm, dateTimeStamp, scope));
            stringToSign.Append(ToHexString(canonicalRequestHashBytes, true));

            string signatureString = string.Empty;

            // compute the signing key
            using (var kha = KeyedHashAlgorithm.Create(Hmac))
            {
                kha.Key = DeriveSigningKey(Hmac, secretKey, this.Region, dateStamp, this.Service);

                // compute the AWS4 signature and return it
                var signature = kha.ComputeHash(Encoding.UTF8.GetBytes(stringToSign.ToString()));
                signatureString = ToHexString(signature, true);
            }

            var authString = new StringBuilder();
            string schemeAlgorithm = string.Format(CultureInfo.CurrentCulture, "{0}-{1} ", Scheme, Algorithm);
            authString.Append(schemeAlgorithm);
            string accessKeyScope = string.Format(CultureInfo.CurrentCulture, "Credential={0}/{1}, ", accessKey, scope);
            authString.Append(accessKeyScope);
            string canonicalHeaderNames = string.Format(CultureInfo.CurrentCulture, "SignedHeaders={0}, ", canonicalizedHeaderNames);
            authString.Append(canonicalHeaderNames);
            string sign = string.Format(CultureInfo.CurrentCulture, "Signature={0}", signatureString);
            authString.Append(sign);
            var authorization = authString.ToString();

            return authorization;
        }

        /// <summary>
        /// Amazon URI
        /// </summary>
        /// <param name="fileName">file name</param>
        /// <param name="container">container</param>
        /// <returns>Full Uri</returns>
        public SignedUrl GetSignedUrl(string fileName, string container)
        {
            AmazonCloud signer = GetSigner(region, bucket, fileName);
            SignedUrl config = new SignedUrl();
            string policy = GetAwsPolicy(bucket, fileName);
            string signature = GetAwsSignature(signer, policy, accessKeyId, secretKey);
            config.Url = "https://" + bucket + ".s3.amazonaws.com/" + fileName + "?" + signature;

            return config;
        }

        /// <summary>
        /// Create Root Container
        /// </summary>
        /// <param name="container">Container</param>
        /// <returns>True if operation is successfull</returns>
        public bool CreateRootContainer(string container)
        {
            // Create the blob client object.
            // CloudBlobClient blobClient = GetBlobClient(storageConnectionString);
            // CloudBlobContainer container = blobClient.GetContainerReference(containerName);

            // Create a new container, if it does not exist
            return true; // container.CreateIfNotExists();
        }

        /// <summary>
        /// Delete File
        /// </summary>
        /// <param name="fileName">File Name</param>
        /// <param name="container">Container</param>
        /// <returns>True/False</returns>
        public bool DeleteFile(string fileName, string container)
        {
            // TODO: Implement DeleteDocument (documentId)
            return true;
        }

        /// <summary>
        /// Possibility to Rename File
        /// </summary>
        /// <param name="fileName">File Name</param>
        /// <param name="newFileName">New File Name</param>
        /// <param name="container">Container</param>
        /// <returns>True or False</returns>
        public bool RenameFile(string fileName, string newFileName, string container)
        {
            // TODO: Implement RenameDocument (documentId)
            return true;
        }

        /// <summary>
        /// Get Root Container for current user
        /// </summary>
        /// <param name="container">Container</param>
        /// <returns>Name of container</returns>
        public string GetRootContainer(string container)
        {
            return containerPrefix + container;
        }

        private static string GetAwsSignature(AmazonCloud signer, string base64PolicyString, string awsAccessKey, string awsSecretKey)
        {
            var result = signer.ComputeSign(new Dictionary<string, string>(), string.Empty, base64PolicyString, awsAccessKey, awsSecretKey);
            return result;
        }

        private static AmazonCloud GetSigner(string region, string bucketName, string fileName)
        {
            var signer = new AmazonCloud
            {
                EndpointUri = new Uri("https://" + bucketName + ".s3.amazonaws.com/" + fileName),
                HttpMethod = "PUT",
                Service = "s3",
                Region = region
            };

            return signer;
        }

        private static string GetAwsPolicy(string bucketName, string fileName)
        {
            var keyName = fileName; // "SamplesPath/POSTedFile.txt";

            var dateTimeStamp = DateTime.UtcNow;

            // construct the policy document governing the POST; note we need to request data from
            // the signer to complete the document ahead of the actual signing. The policy does not
            // need newlines but the sample uses them to make the resulting document clearer to read.
            // The double {{ and }} are needed to escape the {} sequences in the document.
            var policyBuilder = new StringBuilder();
            int expire = int.Parse(expireTime, CultureInfo.CurrentCulture);
            policyBuilder.Append(string.Format(CultureInfo.CurrentCulture, "{{ \"expiration\": \"{0}\"\n", dateTimeStamp.AddMinutes(expire).ToString("2013-08-07T12:00:00.000Z", CultureInfo.CurrentCulture)));
            policyBuilder.Append("\"conditions\" : [");
            policyBuilder.Append(string.Format(CultureInfo.CurrentCulture, "{{ \"bucket\": \"{0}\"\n", bucketName));
            policyBuilder.Append(string.Format(CultureInfo.CurrentCulture, "[ \"starts-with\", \"$key\", \"{0}\"]\n", keyName));
            policyBuilder.Append("{{ \"acl\" : \"public-read\" }\n");
            policyBuilder.Append(string.Format(CultureInfo.CurrentCulture, "{{ \"success_action_redirect\" : \"http://{0}.s3.amazonaws.com/successful_upload.html\" }}\n", bucketName));

            // policyBuilder.Append("[ \"starts-with\", \"$Content-Type\", \"text/\"]\n");
            policyBuilder.Append("[ \"starts-with\", \"$Content-Type\", \"\"]\n");

            // policyBuilder.AppendFormat("{{ \"{0}\" : \"14365123651274\" }}\n", AWS4SignerBase.XAmzMetaUUID);
            policyBuilder.Append("[\"starts-with\", \"$x-amz-meta-tag\", \"\"]\n");

            // populate these with assistance from the signer
            policyBuilder.Append(string.Format(CultureInfo.CurrentCulture, "{{ \"{0}\" : \"{1}\"}}\n", Credential, FormatCredentialStringForPolicy()));
            policyBuilder.Append(string.Format(CultureInfo.CurrentCulture, "{{ \"{0}\" : \"{1}\"}}\n", Algorithm, FormatAlgorithmForPolicy));
            policyBuilder.Append(string.Format(CultureInfo.CurrentCulture, "{{ \"{0}\" : \"{1}\" }}\n", Date, FormatDateTimeForPolicy(dateTimeStamp)));
            policyBuilder.Append("]\n}");

            // hash the Base64 version of the policy document and pass this to the signer as the body hash
            var policyStringBytes = Encoding.UTF8.GetBytes(policyBuilder.ToString());
            var base64PolicyString = Convert.ToBase64String(policyStringBytes);

            return base64PolicyString;
        }
    }
}

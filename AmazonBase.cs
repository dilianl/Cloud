// <copyright file="AmazonBase.cs" company="Negometrix">
// Copyright © Negometrix. All rights reserved.
// </copyright>
// <summary>Contains AmazonBase class.</summary>
namespace NX1.Clouds.CloudStorage.Amazon
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;

    /// <summary>
    /// Common methods and properties for all Aws signer variants
    /// </summary>
    public class AmazonBase
    {
        /// <summary>
        /// SHA256 hash of an empty request body
        /// </summary>
        public const string Body = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        /// <summary>
        /// SCHEME
        /// </summary>
        public const string Scheme = "AWS4";

        /// <summary>
        /// ALGORITHM
        /// </summary>
        public const string Algorithm = "HMAC-SHA256";

        /// <summary>
        /// TERMINATOR
        /// </summary>
        public const string Terminator = "aws4_request";

        /// <summary>
        /// format strings for the date/time and date stamps required during signing
        /// </summary>
        public const string BasicFormat = "yyyyMMddTHHmmssZ";

        /// <summary>
        /// Date String Format
        /// </summary>
        public const string DateStringFormat = "yyyyMMdd";

        /// <summary>
        /// some common x-amz-* parameters
        /// </summary>
        public const string AlgorithmX = "X-Amz-Algorithm";

        /// <summary>
        /// X_Amz_Credential
        /// </summary>
        public const string Credential = "X-Amz-Credential";

        /// <summary>
        /// X_Amz_SignedHeaders
        /// </summary>
        public const string SignedHeaders = "X-Amz-SignedHeaders";

        /// <summary>
        /// X_Amz_Date
        /// </summary>
        public const string Date = "X-Amz-Date";

        /// <summary>
        /// X_Amz_Signature
        /// </summary>
        public const string Signature = "X-Amz-Signature";

        /// <summary>
        /// X_Amz_Expires
        /// </summary>
        public const string Expires = "X-Amz-Expires";

        /// <summary>
        /// X_Amz_Content_SHA256
        /// </summary>
        public const string Content = "X-Amz-Content-SHA256";

        /// <summary>
        /// X_Amz_Decoded_Content_Length
        /// </summary>
        public const string ContentLength = "X-Amz-Decoded-Content-Length";

        /// <summary>
        /// X_Amz_Meta_UUID
        /// </summary>
        public const string Meta = "X-Amz-Meta-UUID";

        /// <summary>
        /// the name of the keyed hash algorithm used in signing
        /// </summary>
        public const string Hmac = "HMACSHA256";

        /// <summary>
        /// request canonicalization requires multiple whitespace compression
        /// </summary>
        private static readonly Regex CompressWhitespaceRegex = new Regex("\\s+");

        /// <summary>
        /// The service endpoint, including the path to any resource.
        /// </summary>
        /// <value>
        /// The service endpoint, including the path to any resource.
        /// </value>
        public Uri EndpointUri { get; set; }

        /// <summary>
        /// The HTTP verb for the request, e.g. GET.
        /// </summary>
        /// <value>
        /// The HTTP verb for the request, e.g. GET.
        /// </value>
        public string HttpMethod { get; set; }

        /// <summary>
        /// The signing name of the service, e.g. 's3'.
        /// </summary>
        /// <value>
        /// The signing name of the service, e.g. 's3'.
        /// </value>
        public string Service { get; set; }

        /// <summary>
        /// The system name of the AWS region associated with the endpoint, e.g. us-east-1.
        /// </summary>
        /// <value>
        /// The system name of the AWS region associated with the endpoint, e.g. us-east-1.
        /// </value>
        public string Region { get; set; }

        /// <summary>
        /// Helper to format a byte array into string
        /// </summary>
        /// <param name="data">The data blob to process</param>
        /// <param name="lowercase">If true, returns hex digits in lower case form</param>
        /// <returns>String version of the data</returns>
        public static string ToHexString(byte[] data, bool lowercase)
        {
            if (data == null)
            {
                throw new ArgumentException("Data is null");
            }

            var sb = new StringBuilder();
            for (var i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString(lowercase ? "x2" : "X2", CultureInfo.InvariantCulture));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Returns the canonical collection of header names that will be included in the signature. For AWS4, all header names must be included in the process in sorted canonicalized order.
        /// </summary>
        /// <param name="headers">
        /// The set of header names and values that will be sent with the request
        /// </param>
        /// <returns>
        /// The set of header names canonicalized to a flattened, ;-delimited string
        /// </returns>
        protected static string CanonicalizeHeaderNames(IDictionary<string, string> headers)
        {
            if (headers == null)
            {
                throw new ArgumentException("Headers is null");
            }

            var headersToSign = new List<string>(headers.Keys);
            headersToSign.Sort(StringComparer.OrdinalIgnoreCase);

            var sb = new StringBuilder();
            foreach (var header in headersToSign)
            {
                if (sb.Length > 0)
                {
                    sb.Append(";");
                }

                sb.Append(header.ToLower(CultureInfo.CurrentCulture));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Returns the canonical request string to go into the signer process; this
        /// consists of several canonical sub-parts.
        /// </summary>
        /// <param name="endpointUri">endpointUri</param>
        /// <param name="httpMethod">httpMethod</param>
        /// <param name="queryParameters">queryParameters</param>
        /// <param name="headerNames">
        /// The set of header names to be included in the signature, formatted as a flattened, ;-delimited string
        /// </param>
        /// <param name="headers">canonicalizedHeaders
        /// </param>
        /// <param name="bodyHash">
        /// Precomputed SHA256 hash of the request body content. For chunked encoding this
        /// should be the fixed string ''.
        /// </param>
        /// <returns>String representing the canonicalized request for signing</returns>
        protected static string CanonicalizeRequest(Uri endpointUri, string httpMethod, string queryParameters, string headerNames, string headers, string bodyHash)
        {
            var canonicalRequest = new StringBuilder();

            canonicalRequest.Append(string.Format(CultureInfo.CurrentCulture, "{0}\n", httpMethod));
            canonicalRequest.Append(string.Format(CultureInfo.CurrentCulture, "{0}\n", CanonicalResourcePath(endpointUri)));
            canonicalRequest.Append(string.Format(CultureInfo.CurrentCulture, "{0}\n", queryParameters));

            canonicalRequest.Append(string.Format(CultureInfo.CurrentCulture, "{0}\n", headers));
            canonicalRequest.Append(string.Format(CultureInfo.CurrentCulture, "{0}\n", headerNames));

            canonicalRequest.Append(bodyHash);

            return canonicalRequest.ToString();
        }

        /// <summary>
        /// Helper routine to url encode canonicalized header names and values for safe
        /// inclusion in the presigned url.
        /// </summary>
        /// <param name="data">The string to encode</param>
        /// <param name="isPath">Whether the string is a URL path or not</param>
        /// <returns>The encoded string</returns>
        protected static string Encode(string data, bool isPath = false)
        {
            if (string.IsNullOrEmpty(data))
            {
                throw new ArgumentException("data is empty");
            }

            // The Set of accepted and valid Url characters per RFC3986. Characters outside of this set will be encoded.
            const string validUrlCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            var encoded = new StringBuilder(data.Length * 2);
            string unreservedChars = string.Concat(validUrlCharacters, isPath ? "/:" : string.Empty);

            foreach (char symbol in Encoding.UTF8.GetBytes(data))
            {
                if (unreservedChars.IndexOf(symbol) != -1)
                {
                    encoded.Append(symbol);
                }
                else
                {
                    encoded.Append("%");
                    encoded.Append(string.Format(CultureInfo.CurrentCulture, "{0:X2}", (int)symbol));
                }
            }

            return encoded.ToString();
        }

        /// <summary>
        /// Returns the canonicalized resource path for the service endpoint
        /// </summary>
        /// <param name="endpointUri">Endpoint to the service/resource</param>
        /// <returns>Canonicalized resource path for the endpoint</returns>
        protected static string CanonicalResourcePath(Uri endpointUri)
        {
            if (endpointUri == null)
            {
                throw new ArgumentException("EndpointUri is empty");
            }

            if (string.IsNullOrEmpty(endpointUri.AbsolutePath))
            {
                throw new ArgumentException("AbsolutePath is empty");
            }

            // encode the path per RFC3986
            return Encode(endpointUri.AbsolutePath, true);
        }

        /// <summary>
        /// Compute and return the hash of a data blob using the specified algorithm
        /// and key
        /// </summary>
        /// <param name="algorithm">Algorithm to use for hashing</param>
        /// <param name="key">Hash key</param>
        /// <param name="data">Data blob</param>
        /// <returns>Hash of the data</returns>
        protected static byte[] ComputeKeyedHash(string algorithm, byte[] key, byte[] data)
        {
            using (var hash = KeyedHashAlgorithm.Create(algorithm))
            {
                hash.Key = key;
                return hash.ComputeHash(data);
            }
        }

        /// <summary>
        /// Compute and return the multi-stage signing key for the request.
        /// </summary>
        /// <param name="algorithm">Hashing algorithm to use</param>
        /// <param name="secretAccessKey">The clear-text AWS secret key</param>
        /// <param name="region">The region in which the service request will be processed</param>
        /// <param name="date">Date of the request, in yyyyMMdd format</param>
        /// <param name="service">The name of the service being called by the request</param>
        /// <returns>Computed signing key</returns>
        protected static byte[] DeriveSigningKey(string algorithm, string secretAccessKey, string region, string date, string service)
        {
            const string ksecretPrefix = Scheme;
            char[] ksecret = null;

            ksecret = (ksecretPrefix + secretAccessKey).ToCharArray();

            byte[] hashDate = ComputeKeyedHash(algorithm, Encoding.UTF8.GetBytes(ksecret), Encoding.UTF8.GetBytes(date));
            byte[] hashRegion = ComputeKeyedHash(algorithm, hashDate, Encoding.UTF8.GetBytes(region));
            byte[] hashService = ComputeKeyedHash(algorithm, hashRegion, Encoding.UTF8.GetBytes(service));
            return ComputeKeyedHash(algorithm, hashService, Encoding.UTF8.GetBytes(Terminator));
        }

        /// <summary>
        /// Computes the canonical headers with values for the request. For AWS4, all headers must be included in the signing process.
        /// </summary>
        /// <param name="headers">The set of headers to be encoded</param>
        /// <returns>Canonicalized string of headers with values</returns>
        protected virtual string CanonicalizeHeaders(IDictionary<string, string> headers)
        {
            if (headers == null || headers.Count == 0)
            {
                return string.Empty;
            }

            // step1: sort the headers into lower-case format; we create a new
            // map to ensure we can do a subsequent key lookup using a lower-case
            // key regardless of how 'headers' was created.
            var sortedHeaderMap = new SortedDictionary<string, string>();
            foreach (var header in headers.Keys)
            {
                sortedHeaderMap.Add(header.ToLower(CultureInfo.CurrentCulture), headers[header]);
            }

            // step2: form the canonical header:value entries in sorted order. Multiple white spaces in the values should be compressed to a single space.
            var sb = new StringBuilder();
            foreach (var header in sortedHeaderMap.Keys)
            {
                var headerValue = CompressWhitespaceRegex.Replace(sortedHeaderMap[header], " ");
                sb.Append(string.Format(CultureInfo.CurrentCulture, "{0}:{1}\n", header, headerValue.Trim()));
            }

            return sb.ToString();
        }
    }
}

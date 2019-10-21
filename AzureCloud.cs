// <copyright file="AzureCloud.cs" company="Negometrix">
// Copyright © Negometrix. All rights reserved.
// </copyright>
// <summary>Contains AzureCloud class.</summary>
namespace NX1.Clouds.CloudStorage.Azure
{
    using System;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Globalization;
    using Microsoft.WindowsAzure.Storage;
    using Microsoft.WindowsAzure.Storage.Blob;
    using Microsoft.WindowsAzure.Storage.Shared.Protocol;
    using Model;
    using Model.Enums;

    /// <summary>
    /// Methods and properties for Azure signer
    /// </summary>
    public class AzureCloud : ICloudStorage
    {
        /// <summary>
        /// Azure Expire Time
        /// </summary>
        private static string azureExpireTime = ConfigurationManager.AppSettings["AzureExpireTime"].ToString();

        /// <summary>
        /// Azure Connection String
        /// </summary>
        private static string storageConnectionString = ConfigurationManager.AppSettings["AzureStorageConnectionString"].ToString();

        /// <summary>
        /// Return container prefix
        /// </summary>
        private static string containerPrefix = ConfigurationManager.AppSettings["AzureContainerTemplate"].ToString();

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
                return CloudStorageType.AzureCloud;
            }
        }

        /// <summary>
        /// Init Cors
        /// </summary>
        /// <param name="blobClient">Blob Client</param>
        [CLSCompliant(false)]
        public static void Initialize(CloudBlobClient blobClient)
        {
            if (blobClient == null)
            {
                throw new ArgumentException("BlobClient is null");
            }

            // CORS should be enabled once at service startup
            // Given a BlobClient, download the current Service Properties
            ServiceProperties blobServiceProperties = blobClient.GetServiceProperties();

            // Enable and Configure CORS
            Configure(blobServiceProperties);

            // Commit the CORS changes into the Service Properties
            blobClient.SetServiceProperties(blobServiceProperties);
        }

        /// <summary>
        /// Configure Cors
        /// </summary>
        /// <param name="serviceProperties">Service Properties</param>
        [CLSCompliant(false)]
        public static void Configure(ServiceProperties serviceProperties)
        {
            if (serviceProperties == null)
            {
                throw new ArgumentException("Service properties is null");
            }

            serviceProperties.Cors = new CorsProperties();
            serviceProperties.Cors.CorsRules.Add(new CorsRule()
            {
                AllowedHeaders = new List<string>() { "*" },
                AllowedMethods = CorsHttpMethods.Put | CorsHttpMethods.Get | CorsHttpMethods.Head | CorsHttpMethods.Post,
                AllowedOrigins = new List<string>() { "*" },
                ExposedHeaders = new List<string>() { "*" },
                MaxAgeInSeconds = 1800 // 30 minutes
            });
        }

        /// <summary>
        /// Azure URI
        /// </summary>
        /// <param name="fileName">file name</param>
        /// <param name="container">container</param>
        /// <returns>Full Uri</returns>
        public SignedUrl GetSignedUrl(string fileName, string container)
        {
            // Create the blob client object.
            CloudBlobClient blobClient = GetBlobClient(storageConnectionString);

            // Get a reference to a container to use for the sample code, and create it if it does not exist.
            string rootContainer = this.GetRootContainer(container);
            CloudBlobContainer blobContainer = blobClient.GetContainerReference(rootContainer);
            blobContainer.CreateIfNotExists();

            SharedAccessBlobPolicy sasConstraints = new SharedAccessBlobPolicy();
            int expireTime = int.Parse(azureExpireTime, CultureInfo.CurrentCulture);
            sasConstraints.SharedAccessExpiryTime = DateTime.UtcNow.AddMinutes(expireTime);
            sasConstraints.Permissions = SharedAccessBlobPermissions.Read | SharedAccessBlobPermissions.Write | SharedAccessBlobPermissions.List;

            // Generate the shared access signature on the container, setting the constraints directly on the signature.
            string sasContainerToken = blobContainer.GetSharedAccessSignature(sasConstraints);

            // Return the URI string for the container, including the SAS token
            SignedUrl config = new SignedUrl();
            config.Container = rootContainer;
            config.Url = blobContainer.Uri.ToString() + "/" + fileName + sasContainerToken;

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
            CloudBlobClient blobClient = GetBlobClient(storageConnectionString);
            string containerName = this.GetRootContainer(container);
            CloudBlobContainer blobContainer = blobClient.GetContainerReference(containerName);

            // Create a new container, if it does not exist
            return blobContainer.CreateIfNotExists();
        }

        /// <summary>
        /// Delete File
        /// </summary>
        /// <param name="fileName">File Name</param>
        /// <param name="container">Container</param>
        /// <returns>True/False</returns>
        public bool DeleteFile(string fileName, string container)
        {
            // Create the blob client object.
            CloudBlobClient blobClient = GetBlobClient(storageConnectionString);

            // Get a reference to a container to use for the sample code, and create it if it does not exist.
            string blobContainer = this.GetRootContainer(container);
            CloudBlobContainer cloudBlobContainer = blobClient.GetContainerReference(blobContainer);
            CloudBlockBlob blobSource = cloudBlobContainer.GetBlockBlobReference(fileName);

            return blobSource.DeleteIfExists();
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
            // Create the blob client object.
            CloudBlobClient blobClient = GetBlobClient(storageConnectionString);

            // Get a reference to a container to use for the sample code, and create it if it does not exist.
            string blobContainer = this.GetRootContainer(container);
            CloudBlobContainer cloudBlobContainer = blobClient.GetContainerReference(blobContainer);
            CloudBlockBlob blobSource = cloudBlobContainer.GetBlockBlobReference(fileName);

            if (blobSource.Exists())
            {
                CloudBlockBlob blobTarget = cloudBlobContainer.GetBlockBlobReference(newFileName);
                blobTarget.StartCopy(blobSource);
                blobSource.Delete();
            }

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

        /// <summary>
        /// Get Blob Client
        /// </summary>
        /// <param name="storageConnectionString">Storage Connection String</param>
        /// <returns>CloudBlobClient</returns>
        private static CloudBlobClient GetBlobClient(string storageConnectionString)
        {
            CloudStorageAccount storageAccount = CloudStorageAccount.Parse(storageConnectionString);
            CloudBlobClient blobClient = storageAccount.CreateCloudBlobClient();

            // Init Cors
            Initialize(blobClient);

            return blobClient;
        }
    }
}

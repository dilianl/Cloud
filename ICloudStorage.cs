// <copyright file="ICloudStorage.cs" company="Negometrix">
// Copyright © Negometrix. All rights reserved.
// </copyright>
// <summary>Contains ICloudStorage interface.</summary>
namespace NX1.Clouds.CloudStorage
{
    using NX1.Model;
    using NX1.Model.Enums;

    /// <summary>
    /// Define a cloud storage.
    /// </summary>
    public interface ICloudStorage
    {
        /// <summary>
        /// Get Cloud Type
        /// </summary>
        /// <value>
        /// Return Enum CloudStorageType
        /// </value>
        CloudStorageType CloudType
        {
             get;
        }

        /// <summary>
        /// Get Signed Url
        /// </summary>
        /// <param name="fileName">File Name</param>
        /// <param name="container">Container</param>
        /// <returns>SignedUrl object</returns>
        SignedUrl GetSignedUrl(string fileName, string container);

        /// <summary>
        /// Possibility to Delete File
        /// </summary>
        /// <param name="fileName">File Name</param>
        /// <param name="container">Container</param>
        /// <returns>True or False</returns>
        bool DeleteFile(string fileName, string container);

        /// <summary>
        /// Possibility to Rename File
        /// </summary>
        /// <param name="fileName">File Name</param>
        /// <param name="newFileName">New File Name</param>
        /// <param name="container">Container</param>
        /// <returns>True or False</returns>
        bool RenameFile(string fileName, string newFileName, string container);

        /// <summary>
        /// Create New Container
        /// </summary>
        /// <param name="container">Container</param>
        /// <returns>True if operation is successfull</returns>
        bool CreateRootContainer(string container);

        /// <summary>
        /// Get User Root Container
        /// </summary>
        /// <param name="container">Container</param>
        /// <returns>Name of container</returns>
        string GetRootContainer(string container);
    }
}

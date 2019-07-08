//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2019 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.IO;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace KeeperSecurity.Sdk
{
    public interface IThumbnailUploadTask
    {
        string MimeType { get; }
        int Size { get; }
        Stream Stream { get; }
    }
    public interface IAttachmentUploadTask
    { 
        string Name { get; }
        string Title { get; }
        string MimeType { get; }
        Stream Stream { get; }

        IThumbnailUploadTask Thumbnail { get; }
    }

    public class FileAttachmentUploadTask : IAttachmentUploadTask, IDisposable
    { 
        public FileAttachmentUploadTask(string fileName) { 
            if (File.Exists(fileName)) {
                Name = Path.GetFileName(fileName);
                Title = Name;
                try {
                    MimeType = MimeTypes.MimeTypeMap.GetMimeType(Path.GetExtension(fileName));
                }
                catch { }
                fileStream_ = File.Open(fileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            } else {
                Trace.TraceError("FileAttachmentUploadTask: fileName: \"{0}\" not found.", fileName);
            }
        }
        private FileStream fileStream_;

        public virtual void PrepareThumbnail() { }

        public string Name { get; set; }
        public string Title { get; set; }
        public string MimeType { get; set; }
        public Stream Stream => fileStream_;
        public IThumbnailUploadTask Thumbnail { get; private set; }

        public void Dispose()
        {
            if (fileStream_ != null) {
                fileStream_.Dispose();
                fileStream_ = null;
            }
            if (Thumbnail != null) {
                if (Thumbnail is IDisposable disp) {
                    disp.Dispose();
                }
            }
        }
    }

    public static class AttachmentExtensions
    {

        public static async Task<WebRequest> CreateAttachmentDownloadRequest(this Vault vault, string recordUid, string attachmentId)
        {
            var command = new RequestDownloadCommand();
            command.RecordUid = recordUid;
            command.fileIDs = new string[] { attachmentId };
            vault.ResolveRecordAccessPath(command);

            var rs = await vault.Auth.ExecuteAuthCommand<RequestDownloadCommand, RequestDownloadResponse>(command);

            var download = rs.downloads[0];
            return WebRequest.Create(new Uri(download.url));
        }

        public static async Task DownloadAttachment(this Vault vault, PasswordRecord record, string attachment, Stream destination)
        {
            if (record.Attachments == null)
            {
                throw new KeeperInvalidParameter("Vault::DownloadAttachment", "record", record.Uid, "has no attachments");
            }
            AttachmentFile attachmentFile = null;
            if (string.IsNullOrEmpty(attachment))
            {
                if (record.Attachments.Count == 1)
                {
                    attachmentFile = record.Attachments[0];
                }
                else
                {
                    throw new KeeperInvalidParameter("Vault::DownloadAttachment", "attachment", "", "is empty");
                }
            }
            else
            {
                attachmentFile = record.Attachments
                    .FirstOrDefault(x =>
                    {
                        if (attachment == x.Id || attachment == x.Name || attachment == x.Title)
                        {
                            return true;
                        }
                        if (x.Thumbnails != null)
                        {
                            var thumbId = x.Thumbnails.Select(y => y.Id).FirstOrDefault(y => y == attachment);
                            if (!string.IsNullOrEmpty(thumbId))
                            {
                                return true;
                            }
                        }
                        return false;
                    });
            }
            if (attachmentFile == null)
            {
                throw new KeeperInvalidParameter("Vault::DownloadAttachment", "attachment", attachment, "not found");
            }

            var attachmentId = attachmentFile.Id;
            if (attachmentFile.Thumbnails != null)
            {
                foreach (var th in attachmentFile.Thumbnails)
                {
                    if (th.Id == attachment)
                    {
                        attachmentId = th.Id;
                        break;
                    }
                }
            }

            var request = await CreateAttachmentDownloadRequest(vault, record.Uid, attachmentId);
            using (var response = await request.GetResponseAsync() as HttpWebResponse)
            {
                using (var stream = response.GetResponseStream())
                {
                    var transform = new DecryptAesV1Transform(attachmentFile.Key.Base64UrlDecode());
                    using (var decodeStream = new CryptoStream(stream, transform, CryptoStreamMode.Read))
                    {
                        if (destination != null) {
                            await decodeStream.CopyToAsync(destination);
                        }
                    }
                }
            }

        }

        internal static async Task UploadSingleFile(UploadParameters upload, Stream source) {
            string boundary = "----------" + DateTime.Now.Ticks.ToString("x");
            byte[] boundaryBytes = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary);

            var request = (HttpWebRequest)WebRequest.Create(new Uri(upload.url));
            request.Method = "POST";
            request.ContentType = "multipart/form-data; boundary=" + boundary;

            using (var requestStream = await Task.Factory.FromAsync(request.BeginGetRequestStream, request.EndGetRequestStream, null))
            {
                string parameterTemplate = "\r\nContent-Disposition: form-data; name=\"{0}\"\r\n\r\n{1}";
                if (upload.parameters != null) { 
                    foreach (var pair in upload.parameters) {
                        await requestStream.WriteAsync(boundaryBytes, 0, boundaryBytes.Length);
                        string formitem = string.Format(parameterTemplate, pair.Key, pair.Value);
                        byte[] formitembytes = System.Text.Encoding.UTF8.GetBytes(formitem);
                        requestStream.Write(formitembytes, 0, formitembytes.Length);
                    }
                }
                await requestStream.WriteAsync(boundaryBytes, 0, boundaryBytes.Length);
                string fileTemplate = "\r\nContent-Disposition: form-data; name=\"{0}\"\r\nContent-Type: application/octet-stream\r\n\r\n";
                var fileItem = string.Format(fileTemplate, upload.fileParameter);
                var fileBytes = Encoding.UTF8.GetBytes(fileItem);
                await requestStream.WriteAsync(fileBytes, 0, fileBytes.Length);

                await source.CopyToAsync(requestStream);

                await requestStream.WriteAsync(boundaryBytes, 0, boundaryBytes.Length);
                var trailer = Encoding.ASCII.GetBytes("--\r\n");
                await requestStream.WriteAsync(trailer, 0, trailer.Length);
            }
            HttpWebResponse response;
            try {
                response = (HttpWebResponse)await Task.Factory.FromAsync(request.BeginGetResponse, request.EndGetResponse, null);
                if ((int)response.StatusCode != upload.successStatusCode)
                {
                    throw new KeeperInvalidParameter("Vault::UploadSingleFile", "StatusCode", response.StatusCode.ToString(), "not success");
                }
            }
            catch (WebException e) {
                response = (HttpWebResponse)e.Response;
                if (response.ContentType == "application/xml") {
                    using (var stream = new MemoryStream()) {
                        await response.GetResponseStream().CopyToAsync(stream);
                        string responseText = Encoding.UTF8.GetString(stream.ToArray());
                        Trace.TraceError(responseText);
                    }

                }
                throw e;
            }
        }

        public static async Task UploadAttachment(this Vault vault, PasswordRecord record, IAttachmentUploadTask uploadTask)
        {
            var fileStream = uploadTask.Stream;
            if (fileStream == null)
            {
                throw new KeeperInvalidParameter("Vault::UploadAttachment", "uploadTask", "GetStream()", "null");
            }
            var thumbStream = uploadTask.Thumbnail?.Stream;
            var command = new RequestUploadCommand();
            command.fileCount = 1;
            command.thumbnailCount = thumbStream != null ? 1 : 0;

            var rs = await vault.Auth.ExecuteAuthCommand<RequestUploadCommand, RequestUpoadResponse>(command);
            if (rs.fileUploads == null || rs.fileUploads.Length < 1) {
                throw new KeeperInvalidParameter("Vault::UploadAttachment", "request_upload", "file_uploads", "empty");
            }

            UploadParameters fileUpload = rs.fileUploads[0];
            UploadParameters thumbUpload = null;
            if (rs.thumbnailUploads != null && rs.thumbnailUploads.Length > 0) {
                thumbUpload = rs.thumbnailUploads[0];
            }

            var key = CryptoUtils.GenerateEncryptionKey();
            var atta = new AttachmentFile { 
                Id = fileUpload.fileID,
                Name = uploadTask.Name,
                Title = uploadTask.Title,
                Key = key.Base64UrlEncode(),
                Type = uploadTask.MimeType,
                LastModified = DateTimeOffset.Now,
            };
            var transform = new EncryptAesV1Transform(key);
            using (var cryptoStream = new CryptoStream(fileStream, transform, CryptoStreamMode.Read)) {
                await UploadSingleFile(fileUpload, cryptoStream);
                atta.Size = transform.EncryptedBytes;
            }
            if (thumbUpload != null) {
                try {
                    transform = new EncryptAesV1Transform(key);
                    using (var cryptoStream = new CryptoStream(thumbStream, transform, CryptoStreamMode.Read))
                    {
                        await UploadSingleFile(thumbUpload, cryptoStream);
                    }
                    var thumbnail = new AttachmentFileThumb
                    {
                        Id = thumbUpload.fileID,
                        Type = uploadTask.Thumbnail.MimeType,
                        Size = uploadTask.Thumbnail.Size
                    };
                    var ts = new AttachmentFileThumb[] { thumbnail };
                    if (atta.Thumbnails == null) {
                        atta.Thumbnails = ts;
                    } else {
                        atta.Thumbnails = atta.Thumbnails.Concat(ts).ToArray();
                    }
                }
                catch (Exception e) {
                    Trace.TraceError("Upload Thumbname: {0}: \"{1}\"", e.GetType().Name, e.Message);
                }
            }

            record.Attachments.Add(atta);
        }
    }

    [DataContract]
    internal class RequestDownloadCommand : AuthorizedCommand, IRecordAccessPath
    {
        public RequestDownloadCommand() : base("request_download") { }

        [DataMember(Name = "file_ids")]
        public string[] fileIDs;

        [DataMember(Name = "record_uid")]
        public string RecordUid { get; set; }

        [DataMember(Name = "shared_folder_uid", EmitDefaultValue = false)]
        public string SharedFolderUid { get; set; }

        [DataMember(Name = "team_uid", EmitDefaultValue = false)]
        public string TeamUid { get; set; }
    }

    [DataContract]
    internal class RequestUploadCommand : AuthorizedCommand
    {
        public RequestUploadCommand() : base("request_upload") { }

        [DataMember(Name = "file_count")]
        public int fileCount = 0;

        [DataMember(Name = "thumbnail_count")]
        public int thumbnailCount = 0;
    }

#pragma warning disable 0649
    [DataContract]
    internal class RequestDownload
    {
        [DataMember(Name = "success_status_code")]
        public int successStatusCode;
        [DataMember(Name = "url")]
        public string url;
    }

    [DataContract]
    [KnownType(typeof(RequestDownload))]
    internal class RequestDownloadResponse : KeeperApiResponse
    {

        [DataMember(Name = "downloads")]
        public RequestDownload[] downloads;
    }

    [DataContract]
    internal class UploadParameters
    {
        [DataMember(Name = "url")]
        public string url;

        [DataMember(Name = "max_size")]
        public long maxSize;

        [DataMember(Name = "success_status_code")]
        public int successStatusCode;

        [DataMember(Name = "file_id")]
        public string fileID;

        [DataMember(Name = "file_parameter")]
        public string fileParameter;

        [DataMember(Name = "parameters")]
        public IDictionary<string, object> parameters;

    }

    [DataContract]
    [KnownType(typeof(UploadParameters))]
    internal class RequestUpoadResponse : KeeperApiResponse
    {
        [DataMember(Name = "file_uploads")]
        public UploadParameters[] fileUploads;

        [DataMember(Name = "thumbnail_uploads")]
        public UploadParameters[] thumbnailUploads;
    }

#pragma warning restore 0649


}

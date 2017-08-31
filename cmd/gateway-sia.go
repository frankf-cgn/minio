/*
 * (C) 2017 David Gore <dvstate@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
)

type siaObjects struct {
	FS       ObjectLayer // Filesystem layer.
	SIAAddr  string      // Address and port of Sia Daemon.
	CacheDir string
}

// newSiaGateway returns Sia gatewaylayer
func newSiaGateway(host string) (GatewayLayer, error) {
	sia := &siaObjects{
		SIAAddr: host,
	}

	// If SIAAddr not provided on command line or ENV, default to:
	if sia.SIAAddr == "" {
		sia.SIAAddr = "127.0.0.1:9980"
	}

	// Create the filesystem layer
	f, err := newFSObjectLayer(sia.CacheDir)
	if err != nil {
		return nil, err
	}
	sia.FS = f

	fmt.Printf("\nSia Gateway Configuration:\n")
	fmt.Printf("  Sia Daemon API Address: %s\n", sia.SIAAddr)
	fmt.Printf("  Cache Directory: %s\n", sia.CacheDir)

	return sia, nil
}

// StorageInfo is not relevant to Sia backend.
func (s *siaObjects) StorageInfo() (si StorageInfo) {
	return s.FS.StorageInfo()
}

func (s *siaObjects) Shutdown() error {
	return s.FS.Shutdown()
}

// MakeBucket creates a new container on Sia backend.
func (s *siaObjects) MakeBucketWithLocation(bucket, location string) error {
	return s.FS.MakeBucketWithLocation(bucket, location)
}

// GetBucketInfo gets bucket metadata.
func (s *siaObjects) GetBucketInfo(bucket string) (bi BucketInfo, e error) {
	return s.FS.GetBucketInfo(bucket)
}

// ListBuckets lists all Sia buckets
func (s *siaObjects) ListBuckets() (buckets []BucketInfo, e error) {
	return s.FS.ListBuckets()
}

// DeleteBucket deletes a bucket on Sia
func (s *siaObjects) DeleteBucket(bucket string) error {
	return s.FS.DeleteBucket(bucket)
}

func (s *siaObjects) ListObjects(bucket string, prefix string, marker string, delimiter string, maxKeys int) (loi ListObjectsInfo, e error) {
	return s.FS.ListObjects(bucket, prefix, marker, delimiter, maxKeys)
}

func (s *siaObjects) ListObjectsV2(bucket, prefix, continuationToken string, fetchOwner bool, delimiter string, maxKeys int) (loi ListObjectsV2Info, e error) {
	return loi, nil
}

func (s *siaObjects) GetObject(bucket string, object string, startOffset int64, length int64, writer io.Writer) error {
	absCacheDir, err := filepath.Abs(s.CacheDir)
	if err != nil {
		return err
	}

	srcFile := pathJoin(absCacheDir, bucket, object)

	derr := get(s.SIAAddr, "/renter/download/"+strings.Replace(object, slashSeparator, "+", -1)+"?destination="+url.QueryEscape(srcFile))
	if derr != nil {
		return &SiaServiceError{Code: "SiaErrorDaemon", Message: derr.Error()}
	}

	return s.FS.GetObject(bucket, object, startOffset, length, writer)
}

// GetObjectInfo reads object info and replies back ObjectInfo
func (s *siaObjects) GetObjectInfo(bucket string, object string) (objInfo ObjectInfo, err error) {
	return s.FS.GetObjectInfo(bucket, object)
}

// PutObject creates a new object with the incoming data,
func (s *siaObjects) PutObject(bucket string, object string, size int64, data io.Reader, metadata map[string]string, sha256sum string) (objInfo ObjectInfo, err error) {
	oi, err := s.FS.PutObject(bucket, object, size, data, metadata, sha256sum)
	if err != nil {
		return objInfo, err
	}

	absCacheDir, err := filepath.Abs(s.CacheDir)
	if err != nil {
		return objInfo, err
	}

	srcFile := pathJoin(absCacheDir, bucket, object)
	derr := post(s.SIAAddr, "/renter/upload/"+strings.Replace(object, slashSeparator, "+", -1), "source="+srcFile)
	if derr != nil {
		s.FS.DeleteObject(bucket, object)
		return oi, &SiaServiceError{Code: "SiaErrorDaemon", Message: derr.Error()}
	}
	return oi, err
}

// CopyObject copies a blob from source container to destination container.
func (s *siaObjects) CopyObject(srcBucket string, srcObject string, destBucket string, destObject string, metadata map[string]string) (objInfo ObjectInfo, e error) {
	return s.FS.CopyObject(srcBucket, srcObject, destBucket, destObject, metadata)
}

// DeleteObject deletes a blob in bucket
func (s *siaObjects) DeleteObject(bucket string, object string) error {
	derr := post(s.SIAAddr, "/renter/delete/"+strings.Replace(object, slashSeparator, "+", -1), "")
	if derr != nil {
		return &SiaServiceError{Code: "SiaErrorDaemon", Message: derr.Error()}
	}

	return s.FS.DeleteObject(bucket, object)
}

// ListMultipartUploads lists all multipart uploads.
func (s *siaObjects) ListMultipartUploads(bucket string, prefix string, keyMarker string, uploadIDMarker string, delimiter string, maxUploads int) (lmi ListMultipartsInfo, e error) {
	return s.FS.ListMultipartUploads(bucket, prefix, keyMarker, uploadIDMarker, delimiter, maxUploads)
}

// NewMultipartUpload upload object in multiple parts
func (s *siaObjects) NewMultipartUpload(bucket string, object string, metadata map[string]string) (uploadID string, err error) {
	return s.FS.NewMultipartUpload(bucket, object, metadata)
}

// CopyObjectPart copy part of object to other bucket and object
func (s *siaObjects) CopyObjectPart(srcBucket string, srcObject string, destBucket string, destObject string, uploadID string, partID int, startOffset int64, length int64) (info PartInfo, err error) {
	return s.FS.CopyObjectPart(srcBucket, srcObject, destBucket, destObject, uploadID, partID, startOffset, length)
}

// PutObjectPart puts a part of object in bucket
func (s *siaObjects) PutObjectPart(bucket string, object string, uploadID string, partID int, size int64, data io.Reader, md5Hex string, sha256sum string) (pi PartInfo, e error) {
	return s.FS.PutObjectPart(bucket, object, uploadID, partID, size, data, md5Hex, sha256sum)
}

// ListObjectParts returns all object parts for specified object in specified bucket
func (s *siaObjects) ListObjectParts(bucket string, object string, uploadID string, partNumberMarker int, maxParts int) (lpi ListPartsInfo, e error) {
	return s.FS.ListObjectParts(bucket, object, uploadID, partNumberMarker, maxParts)
}

// AbortMultipartUpload aborts a ongoing multipart upload
func (s *siaObjects) AbortMultipartUpload(bucket string, object string, uploadID string) error {
	return s.FS.AbortMultipartUpload(bucket, object, uploadID)
}

// CompleteMultipartUpload completes ongoing multipart upload and finalizes object
func (s *siaObjects) CompleteMultipartUpload(bucket string, object string, uploadID string, uploadedParts []completePart) (oi ObjectInfo, err error) {
	oi, err = s.FS.CompleteMultipartUpload(bucket, object, uploadID, uploadedParts)
	if err != nil {
		return oi, err
	}

	absCacheDir, err := filepath.Abs(s.CacheDir)
	if err != nil {
		return oi, err
	}

	srcFile := pathJoin(absCacheDir, bucket, object)
	derr := post(s.SIAAddr, "/renter/upload/"+strings.Replace(object, slashSeparator, "+", -1), "source="+srcFile)
	if derr != nil {
		s.FS.DeleteObject(bucket, object)
		return oi, &SiaServiceError{Code: "SiaErrorDaemon", Message: derr.Error()}
	}

	return oi, nil
}

/*
 * Minio Cloud Storage, (C) 2017 Minio, Inc.
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

// Package ldap is a simple ldap client to authenticate a user with ldap server.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"gopkg.in/ldap.v2"
)

// Client - represents all the configurable params.
type Client struct {
	*ldap.Conn

	// LDAP host and port. Port usually defaults to 389.
	Host string
	Port string

	// LDAP base and read only user configuration
	Base         string
	BindDN       string
	BindPassword string

	// Configurable query attributes.
	Attributes []string
	UserFilter string

	// TLS related configuration.
	TLSServerName         string
	TLSInsecureSkipVerify bool
	UseSSL                bool
	ClientCertificates    []tls.Certificate // Add client certificates
}

// Dial - dials to the configured ldap backend.
func (lc *Client) Dial() error {
	// If already connected nothing to do.
	if lc.Conn != nil {
		return nil
	}
	l, err := ldap.Dial("tcp", net.JoinHostPort(lc.Host, lc.Port))
	if err != nil {
		return err
	}
	if lc.UseSSL {
		if err = l.StartTLS(&tls.Config{
			InsecureSkipVerify: lc.TLSInsecureSkipVerify,
			ServerName:         lc.TLSServerName,
			Certificates:       lc.ClientCertificates,
		}); err != nil {
			return err
		}
	}
	lc.Conn = l
	return nil
}

// UserExists - searches and validates if user exists, returns true if found.
func (lc *Client) UserExists(username string) (bool, error) {
	if lc.Conn == nil {
		return false, errors.New("Not connected, please Dial() first")
	}

	// First bind with a read only user if any.
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return false, err
		}
	}

	attributes := append(lc.Attributes, "dn")

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return false, err
	}

	if len(sr.Entries) < 1 {
		return false, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return false, errors.New("Too many entries returned")
	}

	return true, nil
}

// Login - attempt a user login against the ldap backend.
func (lc *Client) Login(username, password string) (map[string]string, error) {
	if lc.Conn == nil {
		return nil, errors.New("Not connected, please Dial() first")
	}

	// First bind with a read only user if any.
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) < 1 {
		return nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := map[string]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValue(attr)
	}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(userDN, password)
	if err != nil {
		return nil, err
	}

	// Rebind as the read only user for any further queries
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return nil, err
		}
	}

	return user, nil
}

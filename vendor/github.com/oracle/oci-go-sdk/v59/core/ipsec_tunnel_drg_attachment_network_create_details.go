// Copyright (c) 2016, 2018, 2022, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
// Code generated. DO NOT EDIT.

// Core Services API
//
// Use the Core Services API to manage resources such as virtual cloud networks (VCNs),
// compute instances, and block storage volumes. For more information, see the console
// documentation for the Networking (https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/overview.htm),
// Compute (https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/computeoverview.htm), and
// Block Volume (https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/overview.htm) services.
//

package core

import (
	"encoding/json"
	"fmt"
	"github.com/oracle/oci-go-sdk/v59/common"
	"strings"
)

// IpsecTunnelDrgAttachmentNetworkCreateDetails Specifies the IPSec tunnel attachment.
type IpsecTunnelDrgAttachmentNetworkCreateDetails struct {

	// The OCID (https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
	Id *string `mandatory:"true" json:"id"`

	// The OCID (https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the IPSec connection.
	CompartmentId *string `mandatory:"true" json:"compartmentId"`

	// The BGP ASN to use for the IPSec connection's route target
	RegionalOciAsn *string `mandatory:"true" json:"regionalOciAsn"`

	// The IPSec connection that contains the attached IPSec tunnel.
	IpsecConnectionId *string `mandatory:"true" json:"ipsecConnectionId"`
}

//GetId returns Id
func (m IpsecTunnelDrgAttachmentNetworkCreateDetails) GetId() *string {
	return m.Id
}

func (m IpsecTunnelDrgAttachmentNetworkCreateDetails) String() string {
	return common.PointerString(m)
}

// ValidateEnumValue returns an error when providing an unsupported enum value
// This function is being called during constructing API request process
// Not recommended for calling this function directly
func (m IpsecTunnelDrgAttachmentNetworkCreateDetails) ValidateEnumValue() (bool, error) {
	errMessage := []string{}

	if len(errMessage) > 0 {
		return true, fmt.Errorf(strings.Join(errMessage, "\n"))
	}
	return false, nil
}

// MarshalJSON marshals to json representation
func (m IpsecTunnelDrgAttachmentNetworkCreateDetails) MarshalJSON() (buff []byte, e error) {
	type MarshalTypeIpsecTunnelDrgAttachmentNetworkCreateDetails IpsecTunnelDrgAttachmentNetworkCreateDetails
	s := struct {
		DiscriminatorParam string `json:"type"`
		MarshalTypeIpsecTunnelDrgAttachmentNetworkCreateDetails
	}{
		"IPSEC_TUNNEL",
		(MarshalTypeIpsecTunnelDrgAttachmentNetworkCreateDetails)(m),
	}

	return json.Marshal(&s)
}
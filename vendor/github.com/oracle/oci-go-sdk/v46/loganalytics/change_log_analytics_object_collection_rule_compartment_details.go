// Copyright (c) 2016, 2018, 2021, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
// Code generated. DO NOT EDIT.

// LogAnalytics API
//
// The LogAnalytics API for the LogAnalytics service.
//

package loganalytics

import (
	"github.com/oracle/oci-go-sdk/v46/common"
)

// ChangeLogAnalyticsObjectCollectionRuleCompartmentDetails New compartment details.
type ChangeLogAnalyticsObjectCollectionRuleCompartmentDetails struct {

	// The OCID (https://docs.cloud.oracle.com/Content/General/Concepts/identifiers.htm) of the compartment to which the rule have to be moved.
	CompartmentId *string `mandatory:"true" json:"compartmentId"`
}

func (m ChangeLogAnalyticsObjectCollectionRuleCompartmentDetails) String() string {
	return common.PointerString(m)
}
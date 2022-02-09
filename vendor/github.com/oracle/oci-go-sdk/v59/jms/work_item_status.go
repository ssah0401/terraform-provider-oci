// Copyright (c) 2016, 2018, 2022, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
// Code generated. DO NOT EDIT.

// Java Management Service API
//
// API for the Java Management Service. Use this API to view, create, and manage Fleets.
//

package jms

// WorkItemStatusEnum Enum with underlying type: string
type WorkItemStatusEnum string

// Set of constants representing the allowable values for WorkItemStatusEnum
const (
	WorkItemStatusAccepted       WorkItemStatusEnum = "ACCEPTED"
	WorkItemStatusInProgress     WorkItemStatusEnum = "IN_PROGRESS"
	WorkItemStatusCanceling      WorkItemStatusEnum = "CANCELING"
	WorkItemStatusCanceled       WorkItemStatusEnum = "CANCELED"
	WorkItemStatusSucceeded      WorkItemStatusEnum = "SUCCEEDED"
	WorkItemStatusNeedsAttention WorkItemStatusEnum = "NEEDS_ATTENTION"
	WorkItemStatusRetrying       WorkItemStatusEnum = "RETRYING"
)

var mappingWorkItemStatusEnum = map[string]WorkItemStatusEnum{
	"ACCEPTED":        WorkItemStatusAccepted,
	"IN_PROGRESS":     WorkItemStatusInProgress,
	"CANCELING":       WorkItemStatusCanceling,
	"CANCELED":        WorkItemStatusCanceled,
	"SUCCEEDED":       WorkItemStatusSucceeded,
	"NEEDS_ATTENTION": WorkItemStatusNeedsAttention,
	"RETRYING":        WorkItemStatusRetrying,
}

// GetWorkItemStatusEnumValues Enumerates the set of values for WorkItemStatusEnum
func GetWorkItemStatusEnumValues() []WorkItemStatusEnum {
	values := make([]WorkItemStatusEnum, 0)
	for _, v := range mappingWorkItemStatusEnum {
		values = append(values, v)
	}
	return values
}

// GetWorkItemStatusEnumStringValues Enumerates the set of values in String for WorkItemStatusEnum
func GetWorkItemStatusEnumStringValues() []string {
	return []string{
		"ACCEPTED",
		"IN_PROGRESS",
		"CANCELING",
		"CANCELED",
		"SUCCEEDED",
		"NEEDS_ATTENTION",
		"RETRYING",
	}
}
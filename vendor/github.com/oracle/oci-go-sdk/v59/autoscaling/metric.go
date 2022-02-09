// Copyright (c) 2016, 2018, 2022, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
// Code generated. DO NOT EDIT.

// Autoscaling API
//
// APIs for dynamically scaling Compute resources to meet application requirements. For more information about
// autoscaling, see Autoscaling (https://docs.cloud.oracle.com/Content/Compute/Tasks/autoscalinginstancepools.htm). For information about the
// Compute service, see Overview of the Compute Service (https://docs.cloud.oracle.com/Content/Compute/Concepts/computeoverview.htm).
//

package autoscaling

import (
	"fmt"
	"github.com/oracle/oci-go-sdk/v59/common"
	"strings"
)

// Metric Metric and threshold details for triggering an autoscaling action.
type Metric struct {
	MetricType MetricMetricTypeEnum `mandatory:"true" json:"metricType"`

	Threshold *Threshold `mandatory:"true" json:"threshold"`
}

func (m Metric) String() string {
	return common.PointerString(m)
}

// ValidateEnumValue returns an error when providing an unsupported enum value
// This function is being called during constructing API request process
// Not recommended for calling this function directly
func (m Metric) ValidateEnumValue() (bool, error) {
	errMessage := []string{}
	if _, ok := mappingMetricMetricTypeEnum[string(m.MetricType)]; !ok && m.MetricType != "" {
		errMessage = append(errMessage, fmt.Sprintf("unsupported enum value for MetricType: %s. Supported values are: %s.", m.MetricType, strings.Join(GetMetricMetricTypeEnumStringValues(), ",")))
	}

	if len(errMessage) > 0 {
		return true, fmt.Errorf(strings.Join(errMessage, "\n"))
	}
	return false, nil
}

// MetricMetricTypeEnum Enum with underlying type: string
type MetricMetricTypeEnum string

// Set of constants representing the allowable values for MetricMetricTypeEnum
const (
	MetricMetricTypeCpuUtilization    MetricMetricTypeEnum = "CPU_UTILIZATION"
	MetricMetricTypeMemoryUtilization MetricMetricTypeEnum = "MEMORY_UTILIZATION"
)

var mappingMetricMetricTypeEnum = map[string]MetricMetricTypeEnum{
	"CPU_UTILIZATION":    MetricMetricTypeCpuUtilization,
	"MEMORY_UTILIZATION": MetricMetricTypeMemoryUtilization,
}

// GetMetricMetricTypeEnumValues Enumerates the set of values for MetricMetricTypeEnum
func GetMetricMetricTypeEnumValues() []MetricMetricTypeEnum {
	values := make([]MetricMetricTypeEnum, 0)
	for _, v := range mappingMetricMetricTypeEnum {
		values = append(values, v)
	}
	return values
}

// GetMetricMetricTypeEnumStringValues Enumerates the set of values in String for MetricMetricTypeEnum
func GetMetricMetricTypeEnumStringValues() []string {
	return []string{
		"CPU_UTILIZATION",
		"MEMORY_UTILIZATION",
	}
}
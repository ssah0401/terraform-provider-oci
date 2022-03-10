// Copyright (c) 2016, 2018, 2022, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
// Code generated. DO NOT EDIT.

package managementdashboard

import (
	"fmt"
	"github.com/oracle/oci-go-sdk/v61/common"
	"net/http"
	"strings"
)

// ListManagementSavedSearchesRequest wrapper for the ListManagementSavedSearches operation
type ListManagementSavedSearchesRequest struct {

	// The ID of the compartment in which to list resources.
	CompartmentId *string `mandatory:"true" contributesTo:"query" name:"compartmentId"`

	// A filter to return only resources that match the entire display name given.
	DisplayName *string `mandatory:"false" contributesTo:"query" name:"displayName"`

	// The client request ID for tracing.
	OpcRequestId *string `mandatory:"false" contributesTo:"header" name:"opc-request-id"`

	// The maximum number of items to return.
	Limit *int `mandatory:"false" contributesTo:"query" name:"limit"`

	// The page token representing the page on which to start retrieving results. This is usually retrieved from a previous list call.
	Page *string `mandatory:"false" contributesTo:"query" name:"page"`

	// The sort order to use, either 'asc' or 'desc'.
	SortOrder ListManagementSavedSearchesSortOrderEnum `mandatory:"false" contributesTo:"query" name:"sortOrder" omitEmpty:"true"`

	// The field to sort by. Only one sort order may be provided. Default order for timeCreated is descending. Default order for displayName is ascending. If no value is specified timeCreated is the default.
	SortBy ListManagementSavedSearchesSortByEnum `mandatory:"false" contributesTo:"query" name:"sortBy" omitEmpty:"true"`

	// Metadata about the request. This information will not be transmitted to the service, but
	// represents information that the SDK will consume to drive retry behavior.
	RequestMetadata common.RequestMetadata
}

func (request ListManagementSavedSearchesRequest) String() string {
	return common.PointerString(request)
}

// HTTPRequest implements the OCIRequest interface
func (request ListManagementSavedSearchesRequest) HTTPRequest(method, path string, binaryRequestBody *common.OCIReadSeekCloser, extraHeaders map[string]string) (http.Request, error) {

	_, err := request.ValidateEnumValue()
	if err != nil {
		return http.Request{}, err
	}
	return common.MakeDefaultHTTPRequestWithTaggedStructAndExtraHeaders(method, path, request, extraHeaders)
}

// BinaryRequestBody implements the OCIRequest interface
func (request ListManagementSavedSearchesRequest) BinaryRequestBody() (*common.OCIReadSeekCloser, bool) {

	return nil, false

}

// RetryPolicy implements the OCIRetryableRequest interface. This retrieves the specified retry policy.
func (request ListManagementSavedSearchesRequest) RetryPolicy() *common.RetryPolicy {
	return request.RequestMetadata.RetryPolicy
}

// ValidateEnumValue returns an error when providing an unsupported enum value
// This function is being called during constructing API request process
// Not recommended for calling this function directly
func (request ListManagementSavedSearchesRequest) ValidateEnumValue() (bool, error) {
	errMessage := []string{}
	if _, ok := GetMappingListManagementSavedSearchesSortOrderEnum(string(request.SortOrder)); !ok && request.SortOrder != "" {
		errMessage = append(errMessage, fmt.Sprintf("unsupported enum value for SortOrder: %s. Supported values are: %s.", request.SortOrder, strings.Join(GetListManagementSavedSearchesSortOrderEnumStringValues(), ",")))
	}
	if _, ok := GetMappingListManagementSavedSearchesSortByEnum(string(request.SortBy)); !ok && request.SortBy != "" {
		errMessage = append(errMessage, fmt.Sprintf("unsupported enum value for SortBy: %s. Supported values are: %s.", request.SortBy, strings.Join(GetListManagementSavedSearchesSortByEnumStringValues(), ",")))
	}
	if len(errMessage) > 0 {
		return true, fmt.Errorf(strings.Join(errMessage, "\n"))
	}
	return false, nil
}

// ListManagementSavedSearchesResponse wrapper for the ListManagementSavedSearches operation
type ListManagementSavedSearchesResponse struct {

	// The underlying http response
	RawResponse *http.Response

	// A list of ManagementSavedSearchCollection instances
	ManagementSavedSearchCollection `presentIn:"body"`

	// Unique Oracle-assigned identifier for the request. If you need to contact
	// Oracle about a particular request, please provide the request ID.
	OpcRequestId *string `presentIn:"header" name:"opc-request-id"`

	// For pagination of a list of items. When paging through a list, if this header appears in the response,
	// then a partial list might have been returned. Include this value as the `page` parameter for the
	// subsequent GET request to get the next batch of items.
	OpcNextPage *string `presentIn:"header" name:"opc-next-page"`
}

func (response ListManagementSavedSearchesResponse) String() string {
	return common.PointerString(response)
}

// HTTPResponse implements the OCIResponse interface
func (response ListManagementSavedSearchesResponse) HTTPResponse() *http.Response {
	return response.RawResponse
}

// ListManagementSavedSearchesSortOrderEnum Enum with underlying type: string
type ListManagementSavedSearchesSortOrderEnum string

// Set of constants representing the allowable values for ListManagementSavedSearchesSortOrderEnum
const (
	ListManagementSavedSearchesSortOrderAsc  ListManagementSavedSearchesSortOrderEnum = "ASC"
	ListManagementSavedSearchesSortOrderDesc ListManagementSavedSearchesSortOrderEnum = "DESC"
)

var mappingListManagementSavedSearchesSortOrderEnum = map[string]ListManagementSavedSearchesSortOrderEnum{
	"ASC":  ListManagementSavedSearchesSortOrderAsc,
	"DESC": ListManagementSavedSearchesSortOrderDesc,
}

var mappingListManagementSavedSearchesSortOrderEnumLowerCase = map[string]ListManagementSavedSearchesSortOrderEnum{
	"asc":  ListManagementSavedSearchesSortOrderAsc,
	"desc": ListManagementSavedSearchesSortOrderDesc,
}

// GetListManagementSavedSearchesSortOrderEnumValues Enumerates the set of values for ListManagementSavedSearchesSortOrderEnum
func GetListManagementSavedSearchesSortOrderEnumValues() []ListManagementSavedSearchesSortOrderEnum {
	values := make([]ListManagementSavedSearchesSortOrderEnum, 0)
	for _, v := range mappingListManagementSavedSearchesSortOrderEnum {
		values = append(values, v)
	}
	return values
}

// GetListManagementSavedSearchesSortOrderEnumStringValues Enumerates the set of values in String for ListManagementSavedSearchesSortOrderEnum
func GetListManagementSavedSearchesSortOrderEnumStringValues() []string {
	return []string{
		"ASC",
		"DESC",
	}
}

// GetMappingListManagementSavedSearchesSortOrderEnum performs case Insensitive comparison on enum value and return the desired enum
func GetMappingListManagementSavedSearchesSortOrderEnum(val string) (ListManagementSavedSearchesSortOrderEnum, bool) {
	enum, ok := mappingListManagementSavedSearchesSortOrderEnumLowerCase[strings.ToLower(val)]
	return enum, ok
}

// ListManagementSavedSearchesSortByEnum Enum with underlying type: string
type ListManagementSavedSearchesSortByEnum string

// Set of constants representing the allowable values for ListManagementSavedSearchesSortByEnum
const (
	ListManagementSavedSearchesSortByTimecreated ListManagementSavedSearchesSortByEnum = "timeCreated"
	ListManagementSavedSearchesSortByDisplayname ListManagementSavedSearchesSortByEnum = "displayName"
)

var mappingListManagementSavedSearchesSortByEnum = map[string]ListManagementSavedSearchesSortByEnum{
	"timeCreated": ListManagementSavedSearchesSortByTimecreated,
	"displayName": ListManagementSavedSearchesSortByDisplayname,
}

var mappingListManagementSavedSearchesSortByEnumLowerCase = map[string]ListManagementSavedSearchesSortByEnum{
	"timecreated": ListManagementSavedSearchesSortByTimecreated,
	"displayname": ListManagementSavedSearchesSortByDisplayname,
}

// GetListManagementSavedSearchesSortByEnumValues Enumerates the set of values for ListManagementSavedSearchesSortByEnum
func GetListManagementSavedSearchesSortByEnumValues() []ListManagementSavedSearchesSortByEnum {
	values := make([]ListManagementSavedSearchesSortByEnum, 0)
	for _, v := range mappingListManagementSavedSearchesSortByEnum {
		values = append(values, v)
	}
	return values
}

// GetListManagementSavedSearchesSortByEnumStringValues Enumerates the set of values in String for ListManagementSavedSearchesSortByEnum
func GetListManagementSavedSearchesSortByEnumStringValues() []string {
	return []string{
		"timeCreated",
		"displayName",
	}
}

// GetMappingListManagementSavedSearchesSortByEnum performs case Insensitive comparison on enum value and return the desired enum
func GetMappingListManagementSavedSearchesSortByEnum(val string) (ListManagementSavedSearchesSortByEnum, bool) {
	enum, ok := mappingListManagementSavedSearchesSortByEnumLowerCase[strings.ToLower(val)]
	return enum, ok
}
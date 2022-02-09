// Copyright (c) 2016, 2018, 2022, Oracle and/or its affiliates.  All rights reserved.
// This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
// Code generated. DO NOT EDIT.

package dataconnectivity

import (
	"fmt"
	"github.com/oracle/oci-go-sdk/v59/common"
	"net/http"
	"strings"
)

// ListDataAssetsRequest wrapper for the ListDataAssets operation
type ListDataAssetsRequest struct {

	// The registry Ocid.
	RegistryId *string `mandatory:"true" contributesTo:"path" name:"registryId"`

	// For list pagination. The value for this parameter is the `opc-next-page` or the `opc-prev-page` response header from the previous `List` call. See List Pagination (https://docs.cloud.oracle.com/iaas/Content/API/Concepts/usingapi.htm#nine).
	Page *string `mandatory:"false" contributesTo:"query" name:"page"`

	// Sets the maximum number of results per page, or items to return in a paginated `List` call. See List Pagination (https://docs.cloud.oracle.com/iaas/Content/API/Concepts/usingapi.htm#nine).
	Limit *int `mandatory:"false" contributesTo:"query" name:"limit"`

	// Specifies the fields to get for an object.
	Fields []string `contributesTo:"query" name:"fields" collectionFormat:"multi"`

	// DataAsset type which needs to be listed while listing dataAssets
	IncludeTypes []string `contributesTo:"query" name:"includeTypes" collectionFormat:"multi"`

	// Specifies the field to sort by. Accepts only one field. By default, when you sort by time fields, results are shown in descending order. All other fields default to ascending order. Sorting related parameters are ignored when parameter `query` is present (search operation and sorting order is by relevance score in descending order).
	SortBy ListDataAssetsSortByEnum `mandatory:"false" contributesTo:"query" name:"sortBy" omitEmpty:"true"`

	// Specifies sort order to use, either `ASC` (ascending) or `DESC` (descending).
	SortOrder ListDataAssetsSortOrderEnum `mandatory:"false" contributesTo:"query" name:"sortOrder" omitEmpty:"true"`

	// Used to filter by the name of the object.
	Name *string `mandatory:"false" contributesTo:"query" name:"name"`

	// Unique Oracle-assigned identifier for the request. If
	// you need to contact Oracle about a particular request,
	// please provide the request ID.
	OpcRequestId *string `mandatory:"false" contributesTo:"header" name:"opc-request-id"`

	// Types which wont be listed while listing dataAsset/Connection
	ExcludeTypes []string `contributesTo:"query" name:"excludeTypes" collectionFormat:"multi"`

	// If value is FAVORITES_ONLY, then only objects marked as favorite by the requesting user will be included in result. If value is NON_FAVORITES_ONLY, then objects marked as favorites by the requesting user will be skipped. If value is ALL or if not specified, all objects, irrespective of favorites or not will be returned. Default is ALL.
	FavoritesQueryParam ListDataAssetsFavoritesQueryParamEnum `mandatory:"false" contributesTo:"query" name:"favoritesQueryParam" omitEmpty:"true"`

	// Unique key of the folder.
	FolderId *string `mandatory:"false" contributesTo:"query" name:"folderId"`

	// Endpoint Ids used for data-plane APIs to filter or prefer specific endpoint.
	EndpointIds []string `contributesTo:"query" name:"endpointIds" collectionFormat:"multi"`

	// Endpoints which will be excluded while listing dataAssets
	ExcludeEndpointIds []string `contributesTo:"query" name:"excludeEndpointIds" collectionFormat:"multi"`

	// Metadata about the request. This information will not be transmitted to the service, but
	// represents information that the SDK will consume to drive retry behavior.
	RequestMetadata common.RequestMetadata
}

func (request ListDataAssetsRequest) String() string {
	return common.PointerString(request)
}

// HTTPRequest implements the OCIRequest interface
func (request ListDataAssetsRequest) HTTPRequest(method, path string, binaryRequestBody *common.OCIReadSeekCloser, extraHeaders map[string]string) (http.Request, error) {

	_, err := request.ValidateEnumValue()
	if err != nil {
		return http.Request{}, err
	}
	return common.MakeDefaultHTTPRequestWithTaggedStructAndExtraHeaders(method, path, request, extraHeaders)
}

// BinaryRequestBody implements the OCIRequest interface
func (request ListDataAssetsRequest) BinaryRequestBody() (*common.OCIReadSeekCloser, bool) {

	return nil, false

}

// RetryPolicy implements the OCIRetryableRequest interface. This retrieves the specified retry policy.
func (request ListDataAssetsRequest) RetryPolicy() *common.RetryPolicy {
	return request.RequestMetadata.RetryPolicy
}

// ValidateEnumValue returns an error when providing an unsupported enum value
// This function is being called during constructing API request process
// Not recommended for calling this function directly
func (request ListDataAssetsRequest) ValidateEnumValue() (bool, error) {
	errMessage := []string{}
	if _, ok := mappingListDataAssetsSortByEnum[string(request.SortBy)]; !ok && request.SortBy != "" {
		errMessage = append(errMessage, fmt.Sprintf("unsupported enum value for SortBy: %s. Supported values are: %s.", request.SortBy, strings.Join(GetListDataAssetsSortByEnumStringValues(), ",")))
	}
	if _, ok := mappingListDataAssetsSortOrderEnum[string(request.SortOrder)]; !ok && request.SortOrder != "" {
		errMessage = append(errMessage, fmt.Sprintf("unsupported enum value for SortOrder: %s. Supported values are: %s.", request.SortOrder, strings.Join(GetListDataAssetsSortOrderEnumStringValues(), ",")))
	}
	if _, ok := mappingListDataAssetsFavoritesQueryParamEnum[string(request.FavoritesQueryParam)]; !ok && request.FavoritesQueryParam != "" {
		errMessage = append(errMessage, fmt.Sprintf("unsupported enum value for FavoritesQueryParam: %s. Supported values are: %s.", request.FavoritesQueryParam, strings.Join(GetListDataAssetsFavoritesQueryParamEnumStringValues(), ",")))
	}
	if len(errMessage) > 0 {
		return true, fmt.Errorf(strings.Join(errMessage, "\n"))
	}
	return false, nil
}

// ListDataAssetsResponse wrapper for the ListDataAssets operation
type ListDataAssetsResponse struct {

	// The underlying http response
	RawResponse *http.Response

	// A list of DataAssetSummaryCollection instances
	DataAssetSummaryCollection `presentIn:"body"`

	// Unique Oracle-assigned identifier for the request. If you need to contact
	// Oracle about a particular request, please provide the request ID.
	OpcRequestId *string `presentIn:"header" name:"opc-request-id"`

	// Retrieves the next page of results. When this header appears in the response, additional pages of results remain. See List Pagination (https://docs.cloud.oracle.com/iaas/Content/API/Concepts/usingapi.htm#nine).
	OpcNextPage *string `presentIn:"header" name:"opc-next-page"`

	// Retrieves the previous page of results. When this header appears in the response, previous pages of results exist. See List Pagination (https://docs.cloud.oracle.com/iaas/Content/API/Concepts/usingapi.htm#nine).
	OpcPrevPage *string `presentIn:"header" name:"opc-prev-page"`

	// Total items in the entire list.
	OpcTotalItems *int `presentIn:"header" name:"opc-total-items"`
}

func (response ListDataAssetsResponse) String() string {
	return common.PointerString(response)
}

// HTTPResponse implements the OCIResponse interface
func (response ListDataAssetsResponse) HTTPResponse() *http.Response {
	return response.RawResponse
}

// ListDataAssetsSortByEnum Enum with underlying type: string
type ListDataAssetsSortByEnum string

// Set of constants representing the allowable values for ListDataAssetsSortByEnum
const (
	ListDataAssetsSortById          ListDataAssetsSortByEnum = "id"
	ListDataAssetsSortByTimecreated ListDataAssetsSortByEnum = "timeCreated"
	ListDataAssetsSortByDisplayname ListDataAssetsSortByEnum = "displayName"
)

var mappingListDataAssetsSortByEnum = map[string]ListDataAssetsSortByEnum{
	"id":          ListDataAssetsSortById,
	"timeCreated": ListDataAssetsSortByTimecreated,
	"displayName": ListDataAssetsSortByDisplayname,
}

// GetListDataAssetsSortByEnumValues Enumerates the set of values for ListDataAssetsSortByEnum
func GetListDataAssetsSortByEnumValues() []ListDataAssetsSortByEnum {
	values := make([]ListDataAssetsSortByEnum, 0)
	for _, v := range mappingListDataAssetsSortByEnum {
		values = append(values, v)
	}
	return values
}

// GetListDataAssetsSortByEnumStringValues Enumerates the set of values in String for ListDataAssetsSortByEnum
func GetListDataAssetsSortByEnumStringValues() []string {
	return []string{
		"id",
		"timeCreated",
		"displayName",
	}
}

// ListDataAssetsSortOrderEnum Enum with underlying type: string
type ListDataAssetsSortOrderEnum string

// Set of constants representing the allowable values for ListDataAssetsSortOrderEnum
const (
	ListDataAssetsSortOrderAsc  ListDataAssetsSortOrderEnum = "ASC"
	ListDataAssetsSortOrderDesc ListDataAssetsSortOrderEnum = "DESC"
)

var mappingListDataAssetsSortOrderEnum = map[string]ListDataAssetsSortOrderEnum{
	"ASC":  ListDataAssetsSortOrderAsc,
	"DESC": ListDataAssetsSortOrderDesc,
}

// GetListDataAssetsSortOrderEnumValues Enumerates the set of values for ListDataAssetsSortOrderEnum
func GetListDataAssetsSortOrderEnumValues() []ListDataAssetsSortOrderEnum {
	values := make([]ListDataAssetsSortOrderEnum, 0)
	for _, v := range mappingListDataAssetsSortOrderEnum {
		values = append(values, v)
	}
	return values
}

// GetListDataAssetsSortOrderEnumStringValues Enumerates the set of values in String for ListDataAssetsSortOrderEnum
func GetListDataAssetsSortOrderEnumStringValues() []string {
	return []string{
		"ASC",
		"DESC",
	}
}

// ListDataAssetsFavoritesQueryParamEnum Enum with underlying type: string
type ListDataAssetsFavoritesQueryParamEnum string

// Set of constants representing the allowable values for ListDataAssetsFavoritesQueryParamEnum
const (
	ListDataAssetsFavoritesQueryParamFavoritesOnly    ListDataAssetsFavoritesQueryParamEnum = "FAVORITES_ONLY"
	ListDataAssetsFavoritesQueryParamNonFavoritesOnly ListDataAssetsFavoritesQueryParamEnum = "NON_FAVORITES_ONLY"
	ListDataAssetsFavoritesQueryParamAll              ListDataAssetsFavoritesQueryParamEnum = "ALL"
)

var mappingListDataAssetsFavoritesQueryParamEnum = map[string]ListDataAssetsFavoritesQueryParamEnum{
	"FAVORITES_ONLY":     ListDataAssetsFavoritesQueryParamFavoritesOnly,
	"NON_FAVORITES_ONLY": ListDataAssetsFavoritesQueryParamNonFavoritesOnly,
	"ALL":                ListDataAssetsFavoritesQueryParamAll,
}

// GetListDataAssetsFavoritesQueryParamEnumValues Enumerates the set of values for ListDataAssetsFavoritesQueryParamEnum
func GetListDataAssetsFavoritesQueryParamEnumValues() []ListDataAssetsFavoritesQueryParamEnum {
	values := make([]ListDataAssetsFavoritesQueryParamEnum, 0)
	for _, v := range mappingListDataAssetsFavoritesQueryParamEnum {
		values = append(values, v)
	}
	return values
}

// GetListDataAssetsFavoritesQueryParamEnumStringValues Enumerates the set of values in String for ListDataAssetsFavoritesQueryParamEnum
func GetListDataAssetsFavoritesQueryParamEnumStringValues() []string {
	return []string{
		"FAVORITES_ONLY",
		"NON_FAVORITES_ONLY",
		"ALL",
	}
}
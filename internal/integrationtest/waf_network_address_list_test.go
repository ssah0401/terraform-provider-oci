// Copyright (c) 2017, 2021, Oracle and/or its affiliates. All rights reserved.
// Licensed under the Mozilla Public License v2.0

package integrationtest

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/oracle/oci-go-sdk/v64/common"
	oci_waf "github.com/oracle/oci-go-sdk/v64/waf"

	"github.com/terraform-providers/terraform-provider-oci/httpreplay"
	"github.com/terraform-providers/terraform-provider-oci/internal/acctest"
	tf_client "github.com/terraform-providers/terraform-provider-oci/internal/client"
	"github.com/terraform-providers/terraform-provider-oci/internal/resourcediscovery"
	"github.com/terraform-providers/terraform-provider-oci/internal/tfresource"
	"github.com/terraform-providers/terraform-provider-oci/internal/utils"
)

var (
	NetworkAddressListRequiredOnlyResource = NetworkAddressListResourceDependencies +
		acctest.GenerateResourceFromRepresentationMap("oci_waf_network_address_list", "test_network_address_list", acctest.Required, acctest.Create, networkAddressListRepresentation)

	NetworkAddressListResourceConfig = NetworkAddressListResourceDependencies +
		acctest.GenerateResourceFromRepresentationMap("oci_waf_network_address_list", "test_network_address_list", acctest.Optional, acctest.Update, networkAddressListRepresentation)

	networkAddressListSingularDataSourceRepresentation = map[string]interface{}{
		"network_address_list_id": acctest.Representation{RepType: acctest.Required, Create: `${oci_waf_network_address_list.test_network_address_list.id}`},
	}

	networkAddressListDataSourceRepresentation = map[string]interface{}{
		"compartment_id": acctest.Representation{RepType: acctest.Required, Create: `${var.compartment_id}`},
		"display_name":   acctest.Representation{RepType: acctest.Optional, Create: `displayName`, Update: `displayName2`},
		"id":             acctest.Representation{RepType: acctest.Optional, Create: `${oci_waf_network_address_list.test_network_address_list.id}`},
		"state":          acctest.Representation{RepType: acctest.Optional, Create: []string{`state`}},
		"filter":         acctest.RepresentationGroup{RepType: acctest.Required, Group: networkAddressListDataSourceFilterRepresentation}}
	networkAddressListDataSourceFilterRepresentation = map[string]interface{}{
		"name":   acctest.Representation{RepType: acctest.Required, Create: `id`},
		"values": acctest.Representation{RepType: acctest.Required, Create: []string{`${oci_waf_network_address_list.test_network_address_list.id}`}},
	}

	networkAddressListRepresentation = map[string]interface{}{
		"compartment_id": acctest.Representation{RepType: acctest.Required, Create: `${var.compartment_id}`},
		"type":           acctest.Representation{RepType: acctest.Required, Create: `ADDRESSES`, Update: `VCN_ADDRESSES`},
		"addresses":      acctest.Representation{RepType: acctest.Optional, Create: []string{`addresses`}, Update: []string{`addresses2`}},
		"defined_tags":   acctest.Representation{RepType: acctest.Optional, Create: `${map("${oci_identity_tag_namespace.tag-namespace1.name}.${oci_identity_tag.tag1.name}", "value")}`, Update: `${map("${oci_identity_tag_namespace.tag-namespace1.name}.${oci_identity_tag.tag1.name}", "updatedValue")}`},
		"display_name":   acctest.Representation{RepType: acctest.Optional, Create: `displayName`, Update: `displayName2`},
		"freeform_tags":  acctest.Representation{RepType: acctest.Optional, Create: map[string]string{"bar-key": "value"}, Update: map[string]string{"Department": "Accounting"}},
		"system_tags":    acctest.Representation{RepType: acctest.Optional, Create: map[string]string{"systemTags": "value"}, Update: map[string]string{"systemTags": "updatedValue"}},
		"vcn_addresses":  acctest.RepresentationGroup{RepType: acctest.Optional, Group: networkAddressListVcnAddressesRepresentation},
	}
	networkAddressListVcnAddressesRepresentation = map[string]interface{}{
		"addresses": acctest.Representation{RepType: acctest.Optional, Create: `addresses`, Update: `addresses2`},
		"vcn_id":    acctest.Representation{RepType: acctest.Optional, Create: `${oci_core_vcn.test_vcn.id}`},
	}

	NetworkAddressListResourceDependencies = acctest.GenerateResourceFromRepresentationMap("oci_core_vcn", "test_vcn", acctest.Required, acctest.Create, vcnRepresentation) +
		DefinedTagsDependencies
)

// issue-routing-tag: waf/default
func TestWafNetworkAddressListResource_basic(t *testing.T) {
	httpreplay.SetScenario("TestWafNetworkAddressListResource_basic")
	defer httpreplay.SaveScenario()

	config := acctest.ProviderTestConfig()

	compartmentId := utils.GetEnvSettingWithBlankDefault("compartment_ocid")
	compartmentIdVariableStr := fmt.Sprintf("variable \"compartment_id\" { default = \"%s\" }\n", compartmentId)

	compartmentIdU := utils.GetEnvSettingWithDefault("compartment_id_for_update", compartmentId)
	compartmentIdUVariableStr := fmt.Sprintf("variable \"compartment_id_for_update\" { default = \"%s\" }\n", compartmentIdU)

	resourceName := "oci_waf_network_address_list.test_network_address_list"
	datasourceName := "data.oci_waf_network_address_lists.test_network_address_lists"
	singularDatasourceName := "data.oci_waf_network_address_list.test_network_address_list"

	var resId, resId2 string
	// Save TF content to Create resource with optional properties. This has to be exactly the same as the config part in the "create with optionals" step in the test.
	acctest.SaveConfigContent(config+compartmentIdVariableStr+NetworkAddressListResourceDependencies+
		acctest.GenerateResourceFromRepresentationMap("oci_waf_network_address_list", "test_network_address_list", acctest.Optional, acctest.Create, networkAddressListRepresentation), "waf", "networkAddressList", t)

	acctest.ResourceTest(t, testAccCheckWafNetworkAddressListDestroy, []resource.TestStep{
		// verify Create
		{
			Config: config + compartmentIdVariableStr + NetworkAddressListResourceDependencies +
				acctest.GenerateResourceFromRepresentationMap("oci_waf_network_address_list", "test_network_address_list", acctest.Required, acctest.Create, networkAddressListRepresentation),
			Check: acctest.ComposeAggregateTestCheckFuncWrapper(
				resource.TestCheckResourceAttr(resourceName, "addresses.#", "1"),
				resource.TestCheckResourceAttr(resourceName, "compartment_id", compartmentId),
				resource.TestCheckResourceAttr(resourceName, "type", "ADDRESSES"),
				resource.TestCheckResourceAttr(resourceName, "vcn_addresses.#", "1"),
				resource.TestCheckResourceAttr(resourceName, "vcn_addresses.0.addresses", "addresses"),
				resource.TestCheckResourceAttrSet(resourceName, "vcn_addresses.0.vcn_id"),

				func(s *terraform.State) (err error) {
					resId, err = acctest.FromInstanceState(s, resourceName, "id")
					return err
				},
			),
		},

		// delete before next Create
		{
			Config: config + compartmentIdVariableStr + NetworkAddressListResourceDependencies,
		},
		// verify Create with optionals
		{
			Config: config + compartmentIdVariableStr + NetworkAddressListResourceDependencies +
				acctest.GenerateResourceFromRepresentationMap("oci_waf_network_address_list", "test_network_address_list", acctest.Optional, acctest.Create, networkAddressListRepresentation),
			Check: acctest.ComposeAggregateTestCheckFuncWrapper(
				resource.TestCheckResourceAttr(resourceName, "addresses.#", "1"),
				resource.TestCheckResourceAttr(resourceName, "compartment_id", compartmentId),
				resource.TestCheckResourceAttr(resourceName, "display_name", "displayName"),
				resource.TestCheckResourceAttr(resourceName, "freeform_tags.%", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
				resource.TestCheckResourceAttrSet(resourceName, "state"),
				resource.TestCheckResourceAttr(resourceName, "system_tags.%", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "time_created"),
				resource.TestCheckResourceAttr(resourceName, "type", "ADDRESSES"),
				resource.TestCheckResourceAttr(resourceName, "vcn_addresses.#", "1"),
				resource.TestCheckResourceAttr(resourceName, "vcn_addresses.0.addresses", "addresses"),
				resource.TestCheckResourceAttrSet(resourceName, "vcn_addresses.0.vcn_id"),

				func(s *terraform.State) (err error) {
					resId, err = acctest.FromInstanceState(s, resourceName, "id")
					if isEnableExportCompartment, _ := strconv.ParseBool(utils.GetEnvSettingWithDefault("enable_export_compartment", "true")); isEnableExportCompartment {
						if errExport := resourcediscovery.TestExportCompartmentWithResourceName(&resId, &compartmentId, resourceName); errExport != nil {
							return errExport
						}
					}
					return err
				},
			),
		},

		// verify Update to the compartment (the compartment will be switched back in the next step)
		{
			Config: config + compartmentIdVariableStr + compartmentIdUVariableStr + NetworkAddressListResourceDependencies +
				acctest.GenerateResourceFromRepresentationMap("oci_waf_network_address_list", "test_network_address_list", acctest.Optional, acctest.Create,
					acctest.RepresentationCopyWithNewProperties(networkAddressListRepresentation, map[string]interface{}{
						"compartment_id": Representation{RepType: acctest.Required, Create: `${var.compartment_id_for_update}`},
					})),
			Check: acctest.ComposeAggregateTestCheckFuncWrapper(
				resource.TestCheckResourceAttr(resourceName, "addresses.#", "1"),
				resource.TestCheckResourceAttr(resourceName, "compartment_id", compartmentIdU),
				resource.TestCheckResourceAttr(resourceName, "display_name", "displayName"),
				resource.TestCheckResourceAttr(resourceName, "freeform_tags.%", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
				resource.TestCheckResourceAttrSet(resourceName, "state"),
				resource.TestCheckResourceAttr(resourceName, "system_tags.%", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "time_created"),
				resource.TestCheckResourceAttr(resourceName, "type", "ADDRESSES"),
				resource.TestCheckResourceAttr(resourceName, "vcn_addresses.#", "1"),
				resource.TestCheckResourceAttr(resourceName, "vcn_addresses.0.addresses", "addresses"),
				resource.TestCheckResourceAttrSet(resourceName, "vcn_addresses.0.vcn_id"),

				func(s *terraform.State) (err error) {
					resId2, err = acctest.FromInstanceState(s, resourceName, "id")
					if resId != resId2 {
						return fmt.Errorf("resource recreated when it was supposed to be updated")
					}
					return err
				},
			),
		},

		// verify updates to updatable parameters
		{
			Config: config + compartmentIdVariableStr + NetworkAddressListResourceDependencies +
				acctest.GenerateResourceFromRepresentationMap("oci_waf_network_address_list", "test_network_address_list", acctest.Optional, acctest.Update, networkAddressListRepresentation),
			Check: acctest.ComposeAggregateTestCheckFuncWrapper(
				resource.TestCheckResourceAttr(resourceName, "addresses.#", "1"),
				resource.TestCheckResourceAttr(resourceName, "compartment_id", compartmentId),
				resource.TestCheckResourceAttr(resourceName, "display_name", "displayName2"),
				resource.TestCheckResourceAttr(resourceName, "freeform_tags.%", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
				resource.TestCheckResourceAttrSet(resourceName, "state"),
				resource.TestCheckResourceAttr(resourceName, "system_tags.%", "1"),
				resource.TestCheckResourceAttrSet(resourceName, "time_created"),
				resource.TestCheckResourceAttr(resourceName, "type", "VCN_ADDRESSES"),
				resource.TestCheckResourceAttr(resourceName, "vcn_addresses.#", "1"),
				resource.TestCheckResourceAttr(resourceName, "vcn_addresses.0.addresses", "addresses2"),
				resource.TestCheckResourceAttrSet(resourceName, "vcn_addresses.0.vcn_id"),

				func(s *terraform.State) (err error) {
					resId2, err = acctest.FromInstanceState(s, resourceName, "id")
					if resId != resId2 {
						return fmt.Errorf("Resource recreated when it was supposed to be updated.")
					}
					return err
				},
			),
		},
		// verify datasource
		{
			Config: config +
				acctest.GenerateDataSourceFromRepresentationMap("oci_waf_network_address_lists", "test_network_address_lists", acctest.Optional, acctest.Update, networkAddressListDataSourceRepresentation) +
				compartmentIdVariableStr + NetworkAddressListResourceDependencies +
				acctest.GenerateResourceFromRepresentationMap("oci_waf_network_address_list", "test_network_address_list", acctest.Optional, acctest.Update, networkAddressListRepresentation),
			Check: acctest.ComposeAggregateTestCheckFuncWrapper(
				resource.TestCheckResourceAttr(datasourceName, "compartment_id", compartmentId),
				resource.TestCheckResourceAttr(datasourceName, "display_name", "displayName2"),
				resource.TestCheckResourceAttr(datasourceName, "id", "id"),
				resource.TestCheckResourceAttr(datasourceName, "state.#", "1"),

				resource.TestCheckResourceAttr(datasourceName, "network_address_list_collection.#", "1"),
				resource.TestCheckResourceAttr(datasourceName, "network_address_list_collection.0.items.#", "1"),
			),
		},
		// verify singular datasource
		{
			Config: config +
				acctest.GenerateDataSourceFromRepresentationMap("oci_waf_network_address_list", "test_network_address_list", acctest.Required, acctest.Create, networkAddressListSingularDataSourceRepresentation) +
				compartmentIdVariableStr + NetworkAddressListResourceConfig,
			Check: acctest.ComposeAggregateTestCheckFuncWrapper(
				resource.TestCheckResourceAttrSet(singularDatasourceName, "network_address_list_id"),

				resource.TestCheckResourceAttr(singularDatasourceName, "addresses.#", "1"),
				resource.TestCheckResourceAttr(singularDatasourceName, "compartment_id", compartmentId),
				resource.TestCheckResourceAttr(singularDatasourceName, "display_name", "displayName2"),
				resource.TestCheckResourceAttr(singularDatasourceName, "freeform_tags.%", "1"),
				resource.TestCheckResourceAttrSet(singularDatasourceName, "id"),
				resource.TestCheckResourceAttrSet(singularDatasourceName, "state"),
				resource.TestCheckResourceAttr(singularDatasourceName, "system_tags.%", "1"),
				resource.TestCheckResourceAttrSet(singularDatasourceName, "time_created"),
				resource.TestCheckResourceAttrSet(singularDatasourceName, "time_updated"),
				resource.TestCheckResourceAttr(singularDatasourceName, "type", "VCN_ADDRESSES"),
				resource.TestCheckResourceAttr(singularDatasourceName, "vcn_addresses.#", "1"),
				resource.TestCheckResourceAttr(singularDatasourceName, "vcn_addresses.0.addresses", "addresses2"),
			),
		},
		// verify resource import
		{
			Config:                  config + NetworkAddressListRequiredOnlyResource,
			ImportState:             true,
			ImportStateVerify:       true,
			ImportStateVerifyIgnore: []string{},
			ResourceName:            resourceName,
		},
	})
}

func testAccCheckWafNetworkAddressListDestroy(s *terraform.State) error {
	noResourceFound := true
	client := acctest.TestAccProvider.Meta().(*tf_client.OracleClients).WafClient()
	for _, rs := range s.RootModule().Resources {
		if rs.Type == "oci_waf_network_address_list" {
			noResourceFound = false
			request := oci_waf.GetNetworkAddressListRequest{}

			tmp := rs.Primary.ID
			request.NetworkAddressListId = &tmp

			request.RequestMetadata.RetryPolicy = tfresource.GetRetryPolicy(true, "waf")

			response, err := client.GetNetworkAddressList(context.Background(), request)

			if err == nil {
				deletedLifecycleStates := map[string]bool{
					string(oci_waf.NetworkAddressListLifecycleStateDeleted): true,
				}
				if _, ok := deletedLifecycleStates[string(response.LifecycleState)]; !ok {
					//resource lifecycle state is not in expected deleted lifecycle states.
					return fmt.Errorf("resource lifecycle state: %s is not in expected deleted lifecycle states", response.LifecycleState)
				}
				//resource lifecycle state is in expected deleted lifecycle states. continue with next one.
				continue
			}

			//Verify that exception is for '404 not found'.
			if failure, isServiceError := common.IsServiceError(err); !isServiceError || failure.GetHTTPStatusCode() != 404 {
				return err
			}
		}
	}
	if noResourceFound {
		return fmt.Errorf("at least one resource was expected from the state file, but could not be found")
	}

	return nil
}

func init() {
	if acctest.DependencyGraph == nil {
		acctest.InitDependencyGraph()
	}
	if !acctest.InSweeperExcludeList("WafNetworkAddressList") {
		resource.AddTestSweepers("WafNetworkAddressList", &resource.Sweeper{
			Name:         "WafNetworkAddressList",
			Dependencies: acctest.DependencyGraph["networkAddressList"],
			F:            sweepWafNetworkAddressListResource,
		})
	}
}

func sweepWafNetworkAddressListResource(compartment string) error {
	wafClient := acctest.GetTestClients(&schema.ResourceData{}).WafClient()
	networkAddressListIds, err := getNetworkAddressListIds(compartment)
	if err != nil {
		return err
	}
	for _, networkAddressListId := range networkAddressListIds {
		if ok := acctest.SweeperDefaultResourceId[networkAddressListId]; !ok {
			deleteNetworkAddressListRequest := oci_waf.DeleteNetworkAddressListRequest{}

			deleteNetworkAddressListRequest.NetworkAddressListId = &networkAddressListId

			deleteNetworkAddressListRequest.RequestMetadata.RetryPolicy = tfresource.GetRetryPolicy(true, "waf")
			_, error := wafClient.DeleteNetworkAddressList(context.Background(), deleteNetworkAddressListRequest)
			if error != nil {
				fmt.Printf("Error deleting NetworkAddressList %s %s, It is possible that the resource is already deleted. Please verify manually \n", networkAddressListId, error)
				continue
			}
			acctest.WaitTillCondition(acctest.TestAccProvider, &networkAddressListId, networkAddressListSweepWaitCondition, time.Duration(3*time.Minute),
				networkAddressListSweepResponseFetchOperation, "waf", true)
		}
	}
	return nil
}

func getNetworkAddressListIds(compartment string) ([]string, error) {
	ids := acctest.GetResourceIdsToSweep(compartment, "NetworkAddressListId")
	if ids != nil {
		return ids, nil
	}
	var resourceIds []string
	compartmentId := compartment
	wafClient := acctest.GetTestClients(&schema.ResourceData{}).WafClient()

	listNetworkAddressListsRequest := oci_waf.ListNetworkAddressListsRequest{}
	listNetworkAddressListsRequest.CompartmentId = &compartmentId
	listNetworkAddressListsRequest.LifecycleState = oci_waf.ListNetworkAddressListsLifecycleStateActive
	listNetworkAddressListsResponse, err := wafClient.ListNetworkAddressLists(context.Background(), listNetworkAddressListsRequest)

	if err != nil {
		return resourceIds, fmt.Errorf("Error getting NetworkAddressList list for compartment id : %s , %s \n", compartmentId, err)
	}
	for _, networkAddressList := range listNetworkAddressListsResponse.Items {
		id := *networkAddressList.Id
		resourceIds = append(resourceIds, id)
		acctest.AddResourceIdToSweeperResourceIdMap(compartmentId, "NetworkAddressListId", id)
	}
	return resourceIds, nil
}

func networkAddressListSweepWaitCondition(response common.OCIOperationResponse) bool {
	// Only stop if the resource is available beyond 3 mins. As there could be an issue for the sweeper to delete the resource and manual intervention required.
	if networkAddressListResponse, ok := response.Response.(oci_waf.GetNetworkAddressListResponse); ok {
		return networkAddressListResponse.LifecycleState != oci_waf.NetworkAddressListLifecycleStateDeleted
	}
	return false
}

func networkAddressListSweepResponseFetchOperation(client *tf_client.OracleClients, resourceId *string, retryPolicy *common.RetryPolicy) error {
	_, err := client.WafClient().GetNetworkAddressList(context.Background(), oci_waf.GetNetworkAddressListRequest{
		NetworkAddressListId: resourceId,
		RequestMetadata: common.RequestMetadata{
			RetryPolicy: retryPolicy,
		},
	})
	return err
}

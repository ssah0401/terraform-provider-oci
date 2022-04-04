// Copyright (c) 2017, 2021, Oracle and/or its affiliates. All rights reserved.
// Licensed under the Mozilla Public License v2.0

package provider

import (
	tf_ai_anomaly_detection "github.com/terraform-providers/terraform-provider-oci/internal/service/ai_anomaly_detection"
	tf_ai_vision "github.com/terraform-providers/terraform-provider-oci/internal/service/ai_vision"
	tf_analytics "github.com/terraform-providers/terraform-provider-oci/internal/service/analytics"
	tf_apigateway "github.com/terraform-providers/terraform-provider-oci/internal/service/apigateway"
	tf_apm "github.com/terraform-providers/terraform-provider-oci/internal/service/apm"
	tf_apm_config "github.com/terraform-providers/terraform-provider-oci/internal/service/apm_config"
	tf_apm_synthetics "github.com/terraform-providers/terraform-provider-oci/internal/service/apm_synthetics"
	tf_appmgmt_control "github.com/terraform-providers/terraform-provider-oci/internal/service/appmgmt_control"
	tf_artifacts "github.com/terraform-providers/terraform-provider-oci/internal/service/artifacts"
	tf_audit "github.com/terraform-providers/terraform-provider-oci/internal/service/audit"
	tf_auto_scaling "github.com/terraform-providers/terraform-provider-oci/internal/service/auto_scaling"
	tf_bastion "github.com/terraform-providers/terraform-provider-oci/internal/service/bastion"
	tf_bds "github.com/terraform-providers/terraform-provider-oci/internal/service/bds"
	tf_blockchain "github.com/terraform-providers/terraform-provider-oci/internal/service/blockchain"
	tf_budget "github.com/terraform-providers/terraform-provider-oci/internal/service/budget"
	tf_certificates_management "github.com/terraform-providers/terraform-provider-oci/internal/service/certificates_management"
	tf_cloud_guard "github.com/terraform-providers/terraform-provider-oci/internal/service/cloud_guard"
	tf_computeinstanceagent "github.com/terraform-providers/terraform-provider-oci/internal/service/computeinstanceagent"
	tf_containerengine "github.com/terraform-providers/terraform-provider-oci/internal/service/containerengine"
	tf_core "github.com/terraform-providers/terraform-provider-oci/internal/service/core"
	tf_data_connectivity "github.com/terraform-providers/terraform-provider-oci/internal/service/data_connectivity"
	tf_data_labeling_service "github.com/terraform-providers/terraform-provider-oci/internal/service/data_labeling_service"
	tf_data_safe "github.com/terraform-providers/terraform-provider-oci/internal/service/data_safe"
	tf_database "github.com/terraform-providers/terraform-provider-oci/internal/service/database"
	tf_database_management "github.com/terraform-providers/terraform-provider-oci/internal/service/database_management"
	tf_database_migration "github.com/terraform-providers/terraform-provider-oci/internal/service/database_migration"
	tf_database_tools "github.com/terraform-providers/terraform-provider-oci/internal/service/database_tools"
	tf_datacatalog "github.com/terraform-providers/terraform-provider-oci/internal/service/datacatalog"
	tf_dataflow "github.com/terraform-providers/terraform-provider-oci/internal/service/dataflow"
	tf_dataintegration "github.com/terraform-providers/terraform-provider-oci/internal/service/dataintegration"
	tf_datascience "github.com/terraform-providers/terraform-provider-oci/internal/service/datascience"
	tf_devops "github.com/terraform-providers/terraform-provider-oci/internal/service/devops"
	tf_dns "github.com/terraform-providers/terraform-provider-oci/internal/service/dns"
	tf_email "github.com/terraform-providers/terraform-provider-oci/internal/service/email"
	tf_events "github.com/terraform-providers/terraform-provider-oci/internal/service/events"
	tf_file_storage "github.com/terraform-providers/terraform-provider-oci/internal/service/file_storage"
	tf_functions "github.com/terraform-providers/terraform-provider-oci/internal/service/functions"
	tf_generic_artifacts_content "github.com/terraform-providers/terraform-provider-oci/internal/service/generic_artifacts_content"
	tf_golden_gate "github.com/terraform-providers/terraform-provider-oci/internal/service/golden_gate"
	tf_health_checks "github.com/terraform-providers/terraform-provider-oci/internal/service/health_checks"
	tf_identity "github.com/terraform-providers/terraform-provider-oci/internal/service/identity"
	tf_identity_data_plane "github.com/terraform-providers/terraform-provider-oci/internal/service/identity_data_plane"
	tf_integration "github.com/terraform-providers/terraform-provider-oci/internal/service/integration"
	tf_jms "github.com/terraform-providers/terraform-provider-oci/internal/service/jms"
	tf_kms "github.com/terraform-providers/terraform-provider-oci/internal/service/kms"
	tf_limits "github.com/terraform-providers/terraform-provider-oci/internal/service/limits"
	tf_load_balancer "github.com/terraform-providers/terraform-provider-oci/internal/service/load_balancer"
	tf_log_analytics "github.com/terraform-providers/terraform-provider-oci/internal/service/log_analytics"
	tf_logging "github.com/terraform-providers/terraform-provider-oci/internal/service/logging"
	tf_management_agent "github.com/terraform-providers/terraform-provider-oci/internal/service/management_agent"
	tf_management_dashboard "github.com/terraform-providers/terraform-provider-oci/internal/service/management_dashboard"
	tf_marketplace "github.com/terraform-providers/terraform-provider-oci/internal/service/marketplace"
	tf_metering_computation "github.com/terraform-providers/terraform-provider-oci/internal/service/metering_computation"
	tf_monitoring "github.com/terraform-providers/terraform-provider-oci/internal/service/monitoring"
	tf_mysql "github.com/terraform-providers/terraform-provider-oci/internal/service/mysql"
	tf_network_load_balancer "github.com/terraform-providers/terraform-provider-oci/internal/service/network_load_balancer"
	tf_nosql "github.com/terraform-providers/terraform-provider-oci/internal/service/nosql"
	tf_object_storage "github.com/terraform-providers/terraform-provider-oci/internal/service/object_storage"
	tf_oce "github.com/terraform-providers/terraform-provider-oci/internal/service/oce"
	tf_ocvp "github.com/terraform-providers/terraform-provider-oci/internal/service/ocvp"
	tf_oda "github.com/terraform-providers/terraform-provider-oci/internal/service/oda"
	tf_ons "github.com/terraform-providers/terraform-provider-oci/internal/service/ons"
	tf_operator_access_control "github.com/terraform-providers/terraform-provider-oci/internal/service/operator_access_control"
	tf_opsi "github.com/terraform-providers/terraform-provider-oci/internal/service/opsi"
	tf_optimizer "github.com/terraform-providers/terraform-provider-oci/internal/service/optimizer"
	tf_osmanagement "github.com/terraform-providers/terraform-provider-oci/internal/service/osmanagement"
	tf_osp_gateway "github.com/terraform-providers/terraform-provider-oci/internal/service/osp_gateway"
	tf_osub_billing_schedule "github.com/terraform-providers/terraform-provider-oci/internal/service/osub_billing_schedule"
	tf_osub_organization_subscription "github.com/terraform-providers/terraform-provider-oci/internal/service/osub_organization_subscription"
	tf_osub_subscription "github.com/terraform-providers/terraform-provider-oci/internal/service/osub_subscription"
	tf_osub_usage "github.com/terraform-providers/terraform-provider-oci/internal/service/osub_usage"
	tf_resourcemanager "github.com/terraform-providers/terraform-provider-oci/internal/service/resourcemanager"
	tf_sch "github.com/terraform-providers/terraform-provider-oci/internal/service/sch"
	tf_secrets "github.com/terraform-providers/terraform-provider-oci/internal/service/secrets"
	tf_service_catalog "github.com/terraform-providers/terraform-provider-oci/internal/service/service_catalog"
	tf_service_manager_proxy "github.com/terraform-providers/terraform-provider-oci/internal/service/service_manager_proxy"
	tf_streaming "github.com/terraform-providers/terraform-provider-oci/internal/service/streaming"
	tf_usage_proxy "github.com/terraform-providers/terraform-provider-oci/internal/service/usage_proxy"
	tf_vault "github.com/terraform-providers/terraform-provider-oci/internal/service/vault"
	tf_visual_builder "github.com/terraform-providers/terraform-provider-oci/internal/service/visual_builder"
	tf_vulnerability_scanning "github.com/terraform-providers/terraform-provider-oci/internal/service/vulnerability_scanning"
	tf_waa "github.com/terraform-providers/terraform-provider-oci/internal/service/waa"
	tf_waas "github.com/terraform-providers/terraform-provider-oci/internal/service/waas"
	tf_waf "github.com/terraform-providers/terraform-provider-oci/internal/service/waf"
)

func init() {
	// ai_anomaly_detection service
	RegisterDatasource("oci_ai_anomaly_detection_ai_private_endpoint", tf_ai_anomaly_detection.AiAnomalyDetectionAiPrivateEndpointDataSource())
	RegisterDatasource("oci_ai_anomaly_detection_data_asset", tf_ai_anomaly_detection.AiAnomalyDetectionDataAssetDataSource())
	RegisterDatasource("oci_ai_anomaly_detection_model", tf_ai_anomaly_detection.AiAnomalyDetectionModelDataSource())
	RegisterDatasource("oci_ai_anomaly_detection_project", tf_ai_anomaly_detection.AiAnomalyDetectionProjectDataSource())
	// ai_vision service
	RegisterDatasource("oci_ai_vision_model", tf_ai_vision.AiVisionModelDataSource())
	RegisterDatasource("oci_ai_vision_project", tf_ai_vision.AiVisionProjectDataSource())
	// analytics service
	RegisterDatasource("oci_analytics_analytics_instance", tf_analytics.AnalyticsAnalyticsInstanceDataSource())
	RegisterDatasource("oci_analytics_analytics_instance_private_access_channel", tf_analytics.AnalyticsAnalyticsInstancePrivateAccessChannelDataSource())
	// apigateway service
	RegisterDatasource("oci_apigateway_api", tf_apigateway.ApigatewayApiDataSource())
	RegisterDatasource("oci_apigateway_api_content", tf_apigateway.ApigatewayApiContentDataSource())
	RegisterDatasource("oci_apigateway_api_deployment_specification", tf_apigateway.ApigatewayApiDeploymentSpecificationDataSource())
	RegisterDatasource("oci_apigateway_api_validation", tf_apigateway.ApigatewayApiValidationDataSource())
	RegisterDatasource("oci_apigateway_certificate", tf_apigateway.ApigatewayCertificateDataSource())
	RegisterDatasource("oci_apigateway_deployment", tf_apigateway.ApigatewayDeploymentDataSource())
	RegisterDatasource("oci_apigateway_gateway", tf_apigateway.ApigatewayGatewayDataSource())
	// apm service
	RegisterDatasource("oci_apm_apm_domain", tf_apm.ApmApmDomainDataSource())
	RegisterDatasource("oci_apm_data_key", tf_apm.ApmDataKeyDataSource())
	// apm_config service
	RegisterDatasource("oci_apm_config_config", tf_apm_config.ApmConfigConfigDataSource())
	// apm_synthetics service
	RegisterDatasource("oci_apm_synthetics_monitor", tf_apm_synthetics.ApmSyntheticsMonitorDataSource())
	RegisterDatasource("oci_apm_synthetics_public_vantage_point", tf_apm_synthetics.ApmSyntheticsPublicVantagePointDataSource())
	RegisterDatasource("oci_apm_synthetics_result", tf_apm_synthetics.ApmSyntheticsResultDataSource())
	RegisterDatasource("oci_apm_synthetics_script", tf_apm_synthetics.ApmSyntheticsScriptDataSource())
	// appmgmt_control service
	RegisterDatasource("oci_appmgmt_control_monitored_instance", tf_appmgmt_control.AppmgmtControlMonitoredInstanceDataSource())
	// artifacts service
	RegisterDatasource("oci_artifacts_container_configuration", tf_artifacts.ArtifactsContainerConfigurationDataSource())
	RegisterDatasource("oci_artifacts_container_image", tf_artifacts.ArtifactsContainerImageDataSource())
	RegisterDatasource("oci_artifacts_container_image_signature", tf_artifacts.ArtifactsContainerImageSignatureDataSource())
	RegisterDatasource("oci_artifacts_container_repository", tf_artifacts.ArtifactsContainerRepositoryDataSource())
	RegisterDatasource("oci_artifacts_generic_artifact", tf_artifacts.ArtifactsGenericArtifactDataSource())
	RegisterDatasource("oci_artifacts_repository", tf_artifacts.ArtifactsRepositoryDataSource())
	// audit service
	RegisterDatasource("oci_audit_audit_event", tf_audit.AuditAuditEventDataSource())
	RegisterDatasource("oci_audit_configuration", tf_audit.AuditConfigurationDataSource())
	// auto_scaling service
	RegisterDatasource("oci_autoscaling_auto_scaling_configuration", tf_auto_scaling.AutoScalingAutoScalingConfigurationDataSource())
	// bastion service
	RegisterDatasource("oci_bastion_bastion", tf_bastion.BastionBastionDataSource())
	RegisterDatasource("oci_bastion_session", tf_bastion.BastionSessionDataSource())
	// bds service
	RegisterDatasource("oci_bds_auto_scaling_configuration", tf_bds.BdsAutoScalingConfigurationDataSource())
	RegisterDatasource("oci_bds_bds_instance", tf_bds.BdsBdsInstanceDataSource())
	RegisterDatasource("oci_bds_bds_instance_api_key", tf_bds.BdsBdsInstanceApiKeyDataSource())
	RegisterDatasource("oci_bds_bds_instance_metastore_config", tf_bds.BdsBdsInstanceMetastoreConfigDataSource())
	// blockchain service
	RegisterDatasource("oci_blockchain_blockchain_platform", tf_blockchain.BlockchainBlockchainPlatformDataSource())
	RegisterDatasource("oci_blockchain_blockchain_platform_patch", tf_blockchain.BlockchainBlockchainPlatformPatchDataSource())
	RegisterDatasource("oci_blockchain_osn", tf_blockchain.BlockchainOsnDataSource())
	RegisterDatasource("oci_blockchain_peer", tf_blockchain.BlockchainPeerDataSource())
	// budget service
	RegisterDatasource("oci_budget_alert_rule", tf_budget.BudgetAlertRuleDataSource())
	RegisterDatasource("oci_budget_budget", tf_budget.BudgetBudgetDataSource())
	// certificates_management service
	RegisterDatasource("oci_certificates_management_association", tf_certificates_management.CertificatesManagementAssociationDataSource())
	RegisterDatasource("oci_certificates_management_ca_bundle", tf_certificates_management.CertificatesManagementCaBundleDataSource())
	RegisterDatasource("oci_certificates_management_certificate", tf_certificates_management.CertificatesManagementCertificateDataSource())
	RegisterDatasource("oci_certificates_management_certificate_authority", tf_certificates_management.CertificatesManagementCertificateAuthorityDataSource())
	RegisterDatasource("oci_certificates_management_certificate_authority_version", tf_certificates_management.CertificatesManagementCertificateAuthorityVersionDataSource())
	RegisterDatasource("oci_certificates_management_certificate_authority_version", tf_certificates_management.CertificatesManagementCertificateAuthorityVersionDataSource())
	RegisterDatasource("oci_certificates_management_certificate_version", tf_certificates_management.CertificatesManagementCertificateVersionDataSource())
	RegisterDatasource("oci_certificates_management_certificate_version", tf_certificates_management.CertificatesManagementCertificateVersionDataSource())
	// cloud_guard service
	RegisterDatasource("oci_cloud_guard_cloud_guard_configuration", tf_cloud_guard.CloudGuardCloudGuardConfigurationDataSource())
	RegisterDatasource("oci_cloud_guard_data_mask_rule", tf_cloud_guard.CloudGuardDataMaskRuleDataSource())
	RegisterDatasource("oci_cloud_guard_detector_recipe", tf_cloud_guard.CloudGuardDetectorRecipeDataSource())
	RegisterDatasource("oci_cloud_guard_managed_list", tf_cloud_guard.CloudGuardManagedListDataSource())
	RegisterDatasource("oci_cloud_guard_responder_recipe", tf_cloud_guard.CloudGuardResponderRecipeDataSource())
	RegisterDatasource("oci_cloud_guard_target", tf_cloud_guard.CloudGuardTargetDataSource())
	// computeinstanceagent service
	RegisterDatasource("oci_computeinstanceagent_instance_agent_plugin", tf_computeinstanceagent.ComputeinstanceagentInstanceAgentPluginDataSource())
	RegisterDatasource("oci_computeinstanceagent_instance_available_plugin", tf_computeinstanceagent.ComputeinstanceagentInstanceAvailablePluginDataSource())
	// containerengine service
	RegisterDatasource("oci_containerengine_cluster", tf_containerengine.ContainerengineClusterDataSource())
	RegisterDatasource("oci_containerengine_cluster_kube_config", tf_containerengine.ContainerengineClusterKubeConfigDataSource())
	RegisterDatasource("oci_containerengine_cluster_option", tf_containerengine.ContainerengineClusterOptionDataSource())
	RegisterDatasource("oci_containerengine_migrate_to_native_vcn_statu", tf_containerengine.ContainerengineMigrateToNativeVcnStatuDataSource())
	RegisterDatasource("oci_containerengine_node_pool", tf_containerengine.ContainerengineNodePoolDataSource())
	RegisterDatasource("oci_containerengine_node_pool_option", tf_containerengine.ContainerengineNodePoolOptionDataSource())
	RegisterDatasource("oci_containerengine_work_request", tf_containerengine.ContainerengineWorkRequestDataSource())
	RegisterDatasource("oci_containerengine_work_request_error", tf_containerengine.ContainerengineWorkRequestErrorDataSource())
	RegisterDatasource("oci_containerengine_work_request_log_entry", tf_containerengine.ContainerengineWorkRequestLogEntryDataSource())
	// core service
	RegisterDatasource("oci_core_app_catalog_listing", tf_core.CoreAppCatalogListingDataSource())
	RegisterDatasource("oci_core_app_catalog_listing_resource_version", tf_core.CoreAppCatalogListingResourceVersionDataSource())
	RegisterDatasource("oci_core_app_catalog_subscription", tf_core.CoreAppCatalogSubscriptionDataSource())
	RegisterDatasource("oci_core_block_volume_replica", tf_core.CoreBlockVolumeReplicaDataSource())
	RegisterDatasource("oci_core_boot_volume", tf_core.CoreBootVolumeDataSource())
	RegisterDatasource("oci_core_boot_volume_attachment", tf_core.CoreBootVolumeAttachmentDataSource())
	RegisterDatasource("oci_core_boot_volume_backup", tf_core.CoreBootVolumeBackupDataSource())
	RegisterDatasource("oci_core_boot_volume_replica", tf_core.CoreBootVolumeReplicaDataSource())
	RegisterDatasource("oci_core_byoip_allocated_range", tf_core.CoreByoipAllocatedRangeDataSource())
	RegisterDatasource("oci_core_byoip_range", tf_core.CoreByoipRangeDataSource())
	RegisterDatasource("oci_core_cluster_network", tf_core.CoreClusterNetworkDataSource())
	RegisterDatasource("oci_core_cluster_network_instance", tf_core.CoreClusterNetworkInstanceDataSource())
	RegisterDatasource("oci_core_compute_capacity_reservation", tf_core.CoreComputeCapacityReservationDataSource())
	RegisterDatasource("oci_core_compute_capacity_reservation_instance", tf_core.CoreComputeCapacityReservationInstanceDataSource())
	RegisterDatasource("oci_core_compute_capacity_reservation_instance_shape", tf_core.CoreComputeCapacityReservationInstanceShapeDataSource())
	RegisterDatasource("oci_core_compute_global_image_capability_schema", tf_core.CoreComputeGlobalImageCapabilitySchemaDataSource())
	RegisterDatasource("oci_core_compute_global_image_capability_schemas_version", tf_core.CoreComputeGlobalImageCapabilitySchemasVersionDataSource())
	RegisterDatasource("oci_core_compute_image_capability_schema", tf_core.CoreComputeImageCapabilitySchemaDataSource())
	RegisterDatasource("oci_core_console_history", tf_core.CoreConsoleHistoryDataSource())
	RegisterDatasource("oci_core_console_history_data", tf_core.CoreConsoleHistoryContentDataSource())
	RegisterDatasource("oci_core_cpe", tf_core.CoreCpeDataSource())
	RegisterDatasource("oci_core_cpe_device_shape", tf_core.CoreCpeDeviceShapeDataSource())
	RegisterDatasource("oci_core_cross_connect", tf_core.CoreCrossConnectDataSource())
	RegisterDatasource("oci_core_cross_connect_group", tf_core.CoreCrossConnectGroupDataSource())
	RegisterDatasource("oci_core_cross_connect_location", tf_core.CoreCrossConnectLocationDataSource())
	RegisterDatasource("oci_core_cross_connect_port_speed_shape", tf_core.CoreCrossConnectPortSpeedShapeDataSource())
	RegisterDatasource("oci_core_cross_connect_status", tf_core.CoreCrossConnectStatusDataSource())
	RegisterDatasource("oci_core_dedicated_vm_host", tf_core.CoreDedicatedVmHostDataSource())
	RegisterDatasource("oci_core_dedicated_vm_host_instance_shape", tf_core.CoreDedicatedVmHostInstanceShapeDataSource())
	RegisterDatasource("oci_core_dedicated_vm_host_shape", tf_core.CoreDedicatedVmHostShapeDataSource())
	RegisterDatasource("oci_core_dedicated_vm_hosts_instance", tf_core.CoreDedicatedVmHostsInstanceDataSource())
	RegisterDatasource("oci_core_dhcp_options", tf_core.CoreDhcpOptionsDataSource())
	RegisterDatasource("oci_core_drg", tf_core.CoreDrgDataSource())
	RegisterDatasource("oci_core_drg_attachment", tf_core.CoreDrgAttachmentDataSource())
	RegisterDatasource("oci_core_drg_route_distribution", tf_core.CoreDrgRouteDistributionDataSource())
	RegisterDatasource("oci_core_drg_route_distribution_statement", tf_core.CoreDrgRouteDistributionStatementDataSource())
	RegisterDatasource("oci_core_drg_route_table", tf_core.CoreDrgRouteTableDataSource())
	RegisterDatasource("oci_core_drg_route_table_route_rule", tf_core.CoreDrgRouteTableRouteRuleDataSource())
	RegisterDatasource("oci_core_fast_connect_provider_service", tf_core.CoreFastConnectProviderServiceDataSource())
	RegisterDatasource("oci_core_fast_connect_provider_service_key", tf_core.CoreFastConnectProviderServiceKeyDataSource())
	RegisterDatasource("oci_core_image", tf_core.CoreImageDataSource())
	RegisterDatasource("oci_core_image_shape", tf_core.CoreImageShapeDataSource())
	RegisterDatasource("oci_core_instance", tf_core.CoreInstanceDataSource())
	RegisterDatasource("oci_core_instance_configuration", tf_core.CoreInstanceConfigurationDataSource())
	RegisterDatasource("oci_core_instance_console_connection", tf_core.CoreInstanceConsoleConnectionDataSource())
	RegisterDatasource("oci_core_instance_credentials", tf_core.CoreInstanceCredentialDataSource())
	RegisterDatasource("oci_core_instance_device", tf_core.CoreInstanceDeviceDataSource())
	RegisterDatasource("oci_core_instance_measured_boot_report", tf_core.CoreInstanceMeasuredBootReportDataSource())
	RegisterDatasource("oci_core_instance_pool", tf_core.CoreInstancePoolDataSource())
	RegisterDatasource("oci_core_instance_pool_instance", tf_core.CoreInstancePoolInstanceDataSource())
	RegisterDatasource("oci_core_instance_pool_load_balancer_attachment", tf_core.CoreInstancePoolLoadBalancerAttachmentDataSource())
	RegisterDatasource("oci_core_internet_gateway", tf_core.CoreInternetGatewayDataSource())
	RegisterDatasource("oci_core_ipsec", tf_core.CoreIpSecConnectionDataSource())
	RegisterDatasource("oci_core_ipsec_config", tf_core.CoreIpSecConnectionDeviceConfigDataSource())
	RegisterDatasource("oci_core_ipsec_status", tf_core.CoreIpSecConnectionDeviceStatusDataSource())
	RegisterDatasource("oci_core_ipsec_connection_tunnel", tf_core.CoreIpSecConnectionTunnelDataSource())
	RegisterDatasource("oci_core_ipsec_algorithm", tf_core.CoreIpsecAlgorithmDataSource())
	RegisterDatasource("oci_core_ipsec_connection_tunnel_error", tf_core.CoreIpsecConnectionTunnelErrorDataSource())
	RegisterDatasource("oci_core_ipsec_connection_tunnel_route", tf_core.CoreIpsecConnectionTunnelRouteDataSource())
	RegisterDatasource("oci_core_ipv6", tf_core.CoreIpv6DataSource())
	RegisterDatasource("oci_core_letter_of_authority", tf_core.CoreLetterOfAuthorityDataSource())
	RegisterDatasource("oci_core_local_peering_gateway", tf_core.CoreLocalPeeringGatewayDataSource())
	RegisterDatasource("oci_core_nat_gateway", tf_core.CoreNatGatewayDataSource())
	RegisterDatasource("oci_core_network_security_group", tf_core.CoreNetworkSecurityGroupDataSource())
	RegisterDatasource("oci_core_network_security_group_security_rule", tf_core.CoreNetworkSecurityGroupSecurityRuleDataSource())
	RegisterDatasource("oci_core_network_security_group_vnic", tf_core.CoreNetworkSecurityGroupVnicDataSource())
	RegisterDatasource("oci_core_peer_region_for_remote_peering", tf_core.CorePeerRegionForRemotePeeringDataSource())
	RegisterDatasource("oci_core_private_ip", tf_core.CorePrivateIpDataSource())
	RegisterDatasource("oci_core_public_ip", tf_core.CorePublicIpDataSource())
	RegisterDatasource("oci_core_public_ip_pool", tf_core.CorePublicIpPoolDataSource())
	RegisterDatasource("oci_core_remote_peering_connection", tf_core.CoreRemotePeeringConnectionDataSource())
	RegisterDatasource("oci_core_route_table", tf_core.CoreRouteTableDataSource())
	RegisterDatasource("oci_core_security_list", tf_core.CoreSecurityListDataSource())
	RegisterDatasource("oci_core_service", tf_core.CoreServiceDataSource())
	RegisterDatasource("oci_core_service_gateway", tf_core.CoreServiceGatewayDataSource())
	RegisterDatasource("oci_core_shape", tf_core.CoreShapeDataSource())
	RegisterDatasource("oci_core_subnet", tf_core.CoreSubnetDataSource())
	RegisterDatasource("oci_core_tunnel_security_association", tf_core.CoreTunnelSecurityAssociationDataSource())
	RegisterDatasource("oci_core_vcn", tf_core.CoreVcnDataSource())
	RegisterDatasource("oci_core_vcn_dns_resolver_association", tf_core.CoreVcnDnsResolverAssociationDataSource())
	RegisterDatasource("oci_core_virtual_circuit", tf_core.CoreVirtualCircuitDataSource())
	RegisterDatasource("oci_core_virtual_circuit_bandwidth_shape", tf_core.CoreVirtualCircuitBandwidthShapeDataSource())
	RegisterDatasource("oci_core_virtual_circuit_public_prefix", tf_core.CoreVirtualCircuitPublicPrefixDataSource())
	RegisterDatasource("oci_core_vlan", tf_core.CoreVlanDataSource())
	RegisterDatasource("oci_core_vnic", tf_core.CoreVnicDataSource())
	RegisterDatasource("oci_core_vnic_attachment", tf_core.CoreVnicAttachmentDataSource())
	RegisterDatasource("oci_core_volume", tf_core.CoreVolumeDataSource())
	RegisterDatasource("oci_core_volume_attachment", tf_core.CoreVolumeAttachmentDataSource())
	RegisterDatasource("oci_core_volume_backup", tf_core.CoreVolumeBackupDataSource())
	RegisterDatasource("oci_core_volume_backup_policy", tf_core.CoreVolumeBackupPolicyDataSource())
	RegisterDatasource("oci_core_volume_backup_policy_assignment", tf_core.CoreVolumeBackupPolicyAssignmentDataSource())
	RegisterDatasource("oci_core_volume_group", tf_core.CoreVolumeGroupDataSource())
	RegisterDatasource("oci_core_volume_group_backup", tf_core.CoreVolumeGroupBackupDataSource())
	RegisterDatasource("oci_core_volume_group_replica", tf_core.CoreVolumeGroupReplicaDataSource())
	// data_connectivity service
	RegisterDatasource("oci_data_connectivity_registry", tf_data_connectivity.DataConnectivityRegistryDataSource())
	RegisterDatasource("oci_data_connectivity_registry_connection", tf_data_connectivity.DataConnectivityRegistryConnectionDataSource())
	RegisterDatasource("oci_data_connectivity_registry_data_asset", tf_data_connectivity.DataConnectivityRegistryDataAssetDataSource())
	RegisterDatasource("oci_data_connectivity_registry_folder", tf_data_connectivity.DataConnectivityRegistryFolderDataSource())
	RegisterDatasource("oci_data_connectivity_registry_type", tf_data_connectivity.DataConnectivityRegistryTypeDataSource())
	// data_labeling_service service
	RegisterDatasource("oci_data_labeling_service_annotation_format", tf_data_labeling_service.DataLabelingServiceAnnotationFormatDataSource())
	RegisterDatasource("oci_data_labeling_service_dataset", tf_data_labeling_service.DataLabelingServiceDatasetDataSource())
	// data_safe service
	RegisterDatasource("oci_data_safe_alert", tf_data_safe.DataSafeAlertDataSource())
	RegisterDatasource("oci_data_safe_alert_analytic", tf_data_safe.DataSafeAlertAnalyticDataSource())
	RegisterDatasource("oci_data_safe_alert_policy", tf_data_safe.DataSafeAlertPolicyDataSource())
	RegisterDatasource("oci_data_safe_alert_policy_rule", tf_data_safe.DataSafeAlertPolicyRuleDataSource())
	RegisterDatasource("oci_data_safe_audit_archive_retrieval", tf_data_safe.DataSafeAuditArchiveRetrievalDataSource())
	RegisterDatasource("oci_data_safe_audit_event", tf_data_safe.DataSafeAuditEventDataSource())
	RegisterDatasource("oci_data_safe_audit_event_analytic", tf_data_safe.DataSafeAuditEventAnalyticDataSource())
	RegisterDatasource("oci_data_safe_audit_policy", tf_data_safe.DataSafeAuditPolicyDataSource())
	RegisterDatasource("oci_data_safe_audit_profile", tf_data_safe.DataSafeAuditProfileDataSource())
	RegisterDatasource("oci_data_safe_audit_profile_analytic", tf_data_safe.DataSafeAuditProfileAnalyticDataSource())
	RegisterDatasource("oci_data_safe_audit_profile_available_audit_volume", tf_data_safe.DataSafeAuditProfileAvailableAuditVolumeDataSource())
	RegisterDatasource("oci_data_safe_audit_profile_collected_audit_volume", tf_data_safe.DataSafeAuditProfileCollectedAuditVolumeDataSource())
	RegisterDatasource("oci_data_safe_audit_trail", tf_data_safe.DataSafeAuditTrailDataSource())
	RegisterDatasource("oci_data_safe_audit_trail_analytic", tf_data_safe.DataSafeAuditTrailAnalyticDataSource())
	RegisterDatasource("oci_data_safe_compatible_formats_for_data_type", tf_data_safe.DataSafeCompatibleFormatsForDataTypeDataSource())
	RegisterDatasource("oci_data_safe_compatible_formats_for_sensitive_type", tf_data_safe.DataSafeCompatibleFormatsForSensitiveTypeDataSource())
	RegisterDatasource("oci_data_safe_data_safe_configuration", tf_data_safe.DataSafeDataSafeConfigurationDataSource())
	RegisterDatasource("oci_data_safe_data_safe_private_endpoint", tf_data_safe.DataSafeDataSafePrivateEndpointDataSource())
	RegisterDatasource("oci_data_safe_discovery_analytic", tf_data_safe.DataSafeDiscoveryAnalyticDataSource())
	RegisterDatasource("oci_data_safe_discovery_job", tf_data_safe.DataSafeDiscoveryJobDataSource())
	RegisterDatasource("oci_data_safe_discovery_jobs_result", tf_data_safe.DataSafeDiscoveryJobsResultDataSource())
	RegisterDatasource("oci_data_safe_library_masking_format", tf_data_safe.DataSafeLibraryMaskingFormatDataSource())
	RegisterDatasource("oci_data_safe_list_user_grant", tf_data_safe.DataSafeListUserGrantDataSource())
	RegisterDatasource("oci_data_safe_masking_analytic", tf_data_safe.DataSafeMaskingAnalyticDataSource())
	RegisterDatasource("oci_data_safe_masking_policies_masking_column", tf_data_safe.DataSafeMaskingPoliciesMaskingColumnDataSource())
	RegisterDatasource("oci_data_safe_masking_policy", tf_data_safe.DataSafeMaskingPolicyDataSource())
	RegisterDatasource("oci_data_safe_masking_report", tf_data_safe.DataSafeMaskingReportDataSource())
	RegisterDatasource("oci_data_safe_masking_reports_masked_column", tf_data_safe.DataSafeMaskingReportsMaskedColumnDataSource())
	RegisterDatasource("oci_data_safe_on_prem_connector", tf_data_safe.DataSafeOnPremConnectorDataSource())
	RegisterDatasource("oci_data_safe_report", tf_data_safe.DataSafeReportDataSource())
	RegisterDatasource("oci_data_safe_report_content", tf_data_safe.DataSafeReportContentDataSource())
	RegisterDatasource("oci_data_safe_report_definition", tf_data_safe.DataSafeReportDefinitionDataSource())
	RegisterDatasource("oci_data_safe_security_assessment", tf_data_safe.DataSafeSecurityAssessmentDataSource())
	RegisterDatasource("oci_data_safe_security_assessment_comparison", tf_data_safe.DataSafeSecurityAssessmentComparisonDataSource())
	RegisterDatasource("oci_data_safe_security_assessment_finding", tf_data_safe.DataSafeSecurityAssessmentFindingDataSource())
	RegisterDatasource("oci_data_safe_sensitive_data_model", tf_data_safe.DataSafeSensitiveDataModelDataSource())
	RegisterDatasource("oci_data_safe_sensitive_data_models_sensitive_column", tf_data_safe.DataSafeSensitiveDataModelsSensitiveColumnDataSource())
	RegisterDatasource("oci_data_safe_sensitive_type", tf_data_safe.DataSafeSensitiveTypeDataSource())
	RegisterDatasource("oci_data_safe_target_alert_policy_association", tf_data_safe.DataSafeTargetAlertPolicyAssociationDataSource())
	RegisterDatasource("oci_data_safe_target_database", tf_data_safe.DataSafeTargetDatabaseDataSource())
	RegisterDatasource("oci_data_safe_target_database_role", tf_data_safe.DataSafeTargetDatabaseRoleDataSource())
	RegisterDatasource("oci_data_safe_target_databases_column", tf_data_safe.DataSafeTargetDatabasesColumnDataSource())
	RegisterDatasource("oci_data_safe_target_databases_schema", tf_data_safe.DataSafeTargetDatabasesSchemaDataSource())
	RegisterDatasource("oci_data_safe_target_databases_table", tf_data_safe.DataSafeTargetDatabasesTableDataSource())
	RegisterDatasource("oci_data_safe_user_assessment", tf_data_safe.DataSafeUserAssessmentDataSource())
	RegisterDatasource("oci_data_safe_user_assessment_comparison", tf_data_safe.DataSafeUserAssessmentComparisonDataSource())
	RegisterDatasource("oci_data_safe_user_assessment_user", tf_data_safe.DataSafeUserAssessmentUserDataSource())
	RegisterDatasource("oci_data_safe_user_assessment_user_analytic", tf_data_safe.DataSafeUserAssessmentUserAnalyticDataSource())
	// database service
	RegisterDatasource("oci_database_autonomous_container_database", tf_database.DatabaseAutonomousContainerDatabaseDataSource())
	RegisterDatasource("oci_database_autonomous_container_database_dataguard_association", tf_database.DatabaseAutonomousContainerDatabaseDataguardAssociationDataSource())
	RegisterDatasource("oci_database_autonomous_container_patch", tf_database.DatabaseAutonomousContainerPatchDataSource())
	RegisterDatasource("oci_database_autonomous_database", tf_database.DatabaseAutonomousDatabaseDataSource())
	RegisterDatasource("oci_database_autonomous_database_backup", tf_database.DatabaseAutonomousDatabaseBackupDataSource())
	RegisterDatasource("oci_database_autonomous_database_dataguard_association", tf_database.DatabaseAutonomousDatabaseDataguardAssociationDataSource())
	RegisterDatasource("oci_database_autonomous_database_instance_wallet_management", tf_database.DatabaseAutonomousDatabaseInstanceWalletManagementDataSource())
	RegisterDatasource("oci_database_autonomous_database_regional_wallet_management", tf_database.DatabaseAutonomousDatabaseRegionalWalletManagementDataSource())
	RegisterDatasource("oci_database_autonomous_database_wallet", tf_database.DatabaseAutonomousDatabaseWalletDataSource())
	RegisterDatasource("oci_database_autonomous_databases_clone", tf_database.DatabaseAutonomousDatabasesCloneDataSource())
	RegisterDatasource("oci_database_autonomous_db_preview_version", tf_database.DatabaseAutonomousDbPreviewVersionDataSource())
	RegisterDatasource("oci_database_autonomous_db_version", tf_database.DatabaseAutonomousDbVersionDataSource())
	RegisterDatasource("oci_database_autonomous_exadata_infrastructure", tf_database.DatabaseAutonomousExadataInfrastructureDataSource())
	RegisterDatasource("oci_database_autonomous_exadata_infrastructure_ocpu", tf_database.DatabaseAutonomousExadataInfrastructureOcpuDataSource())
	RegisterDatasource("oci_database_autonomous_exadata_infrastructure_shape", tf_database.DatabaseAutonomousExadataInfrastructureShapeDataSource())
	RegisterDatasource("oci_database_autonomous_patch", tf_database.DatabaseAutonomousPatchDataSource())
	RegisterDatasource("oci_database_autonomous_vm_cluster", tf_database.DatabaseAutonomousVmClusterDataSource())
	RegisterDatasource("oci_database_backup", tf_database.DatabaseBackupDataSource())
	RegisterDatasource("oci_database_backup_destination", tf_database.DatabaseBackupDestinationDataSource())
	RegisterDatasource("oci_database_cloud_autonomous_vm_cluster", tf_database.DatabaseCloudAutonomousVmClusterDataSource())
	RegisterDatasource("oci_database_cloud_exadata_infrastructure", tf_database.DatabaseCloudExadataInfrastructureDataSource())
	RegisterDatasource("oci_database_cloud_vm_cluster", tf_database.DatabaseCloudVmClusterDataSource())
	RegisterDatasource("oci_database_data_guard_association", tf_database.DatabaseDataGuardAssociationDataSource())
	RegisterDatasource("oci_database_database", tf_database.DatabaseDatabaseDataSource())
	RegisterDatasource("oci_database_database_pdb_conversion_history_entry", tf_database.DatabaseDatabasePdbConversionHistoryEntryDataSource())
	RegisterDatasource("oci_database_database_software_image", tf_database.DatabaseDatabaseSoftwareImageDataSource())
	RegisterDatasource("oci_database_database_upgrade_history_entry", tf_database.DatabaseDatabaseUpgradeHistoryEntryDataSource())
	RegisterDatasource("oci_database_db_home", tf_database.DatabaseDbHomeDataSource())
	RegisterDatasource("oci_database_db_home_patch", tf_database.DatabaseDbHomePatchDataSource())
	RegisterDatasource("oci_database_db_home_patch_history_entry", tf_database.DatabaseDbHomePatchHistoryEntryDataSource())
	RegisterDatasource("oci_database_db_node", tf_database.DatabaseDbNodeDataSource())
	RegisterDatasource("oci_database_db_node_console_connection", tf_database.DatabaseDbNodeConsoleConnectionDataSource())
	RegisterDatasource("oci_database_db_server", tf_database.DatabaseDbServerDataSource())
	RegisterDatasource("oci_database_db_system", tf_database.DatabaseDbSystemDataSource())
	RegisterDatasource("oci_database_db_system_patch", tf_database.DatabaseDbSystemPatchDataSource())
	RegisterDatasource("oci_database_db_system_patch_history_entry", tf_database.DatabaseDbSystemPatchHistoryEntryDataSource())
	RegisterDatasource("oci_database_db_system_shape", tf_database.DatabaseDbSystemShapeDataSource())
	RegisterDatasource("oci_database_db_version", tf_database.DatabaseDbVersionDataSource())
	RegisterDatasource("oci_database_exadata_infrastructure", tf_database.DatabaseExadataInfrastructureDataSource())
	RegisterDatasource("oci_database_exadata_infrastructure_download_config_file", tf_database.DatabaseExadataInfrastructureDownloadConfigFileDataSource())
	RegisterDatasource("oci_database_exadata_iorm_config", tf_database.DatabaseExadataIormConfigDataSource())
	RegisterDatasource("oci_database_external_container_database", tf_database.DatabaseExternalContainerDatabaseDataSource())
	RegisterDatasource("oci_database_external_database_connector", tf_database.DatabaseExternalDatabaseConnectorDataSource())
	RegisterDatasource("oci_database_external_non_container_database", tf_database.DatabaseExternalNonContainerDatabaseDataSource())
	RegisterDatasource("oci_database_external_pluggable_database", tf_database.DatabaseExternalPluggableDatabaseDataSource())
	RegisterDatasource("oci_database_flex_component", tf_database.DatabaseFlexComponentDataSource())
	RegisterDatasource("oci_database_gi_version", tf_database.DatabaseGiVersionDataSource())
	RegisterDatasource("oci_database_key_store", tf_database.DatabaseKeyStoreDataSource())
	RegisterDatasource("oci_database_maintenance_run", tf_database.DatabaseMaintenanceRunDataSource())
	RegisterDatasource("oci_database_pluggable_database", tf_database.DatabasePluggableDatabaseDataSource())
	RegisterDatasource("oci_database_vm_cluster", tf_database.DatabaseVmClusterDataSource())
	RegisterDatasource("oci_database_vm_cluster_network", tf_database.DatabaseVmClusterNetworkDataSource())
	RegisterDatasource("oci_database_vm_cluster_network_download_config_file", tf_database.DatabaseVmClusterNetworkDownloadConfigFileDataSource())
	RegisterDatasource("oci_database_vm_cluster_patch", tf_database.DatabaseVmClusterPatchDataSource())
	RegisterDatasource("oci_database_vm_cluster_patch_history_entry", tf_database.DatabaseVmClusterPatchHistoryEntryDataSource())
	RegisterDatasource("oci_database_vm_cluster_recommended_network", tf_database.DatabaseVmClusterRecommendedNetworkDataSource())
	RegisterDatasource("oci_database_vm_cluster_update", tf_database.DatabaseVmClusterUpdateDataSource())
	RegisterDatasource("oci_database_vm_cluster_update_history_entry", tf_database.DatabaseVmClusterUpdateHistoryEntryDataSource())
	// database_management service
	RegisterDatasource("oci_database_management_db_management_private_endpoint", tf_database_management.DatabaseManagementDbManagementPrivateEndpointDataSource())
	RegisterDatasource("oci_database_management_db_management_private_endpoint_associated_database", tf_database_management.DatabaseManagementDbManagementPrivateEndpointAssociatedDatabaseDataSource())
	RegisterDatasource("oci_database_management_job_executions_status", tf_database_management.DatabaseManagementJobExecutionsStatusDataSource())
	RegisterDatasource("oci_database_management_managed_database", tf_database_management.DatabaseManagementManagedDatabaseDataSource())
	RegisterDatasource("oci_database_management_managed_database_group", tf_database_management.DatabaseManagementManagedDatabaseGroupDataSource())
	RegisterDatasource("oci_database_management_managed_database_sql_tuning_advisor_task", tf_database_management.DatabaseManagementManagedDatabaseSqlTuningAdvisorTaskDataSource())
	RegisterDatasource("oci_database_management_managed_database_sql_tuning_advisor_tasks_execution_plan_stats_comparision", tf_database_management.DatabaseManagementManagedDatabaseSqlTuningAdvisorTasksExecutionPlanStatsComparisionDataSource())
	RegisterDatasource("oci_database_management_managed_database_sql_tuning_advisor_tasks_finding", tf_database_management.DatabaseManagementManagedDatabaseSqlTuningAdvisorTasksFindingDataSource())
	RegisterDatasource("oci_database_management_managed_database_sql_tuning_advisor_tasks_recommendation", tf_database_management.DatabaseManagementManagedDatabaseSqlTuningAdvisorTasksRecommendationDataSource())
	RegisterDatasource("oci_database_management_managed_database_sql_tuning_advisor_tasks_sql_execution_plan", tf_database_management.DatabaseManagementManagedDatabaseSqlTuningAdvisorTasksSqlExecutionPlanDataSource())
	RegisterDatasource("oci_database_management_managed_database_sql_tuning_advisor_tasks_summary_report", tf_database_management.DatabaseManagementManagedDatabaseSqlTuningAdvisorTasksSummaryReportDataSource())
	RegisterDatasource("oci_database_management_managed_database_user", tf_database_management.DatabaseManagementManagedDatabaseUserDataSource())
	RegisterDatasource("oci_database_management_managed_database_user_consumer_group_privilege", tf_database_management.DatabaseManagementManagedDatabaseUserConsumerGroupPrivilegeDataSource())
	RegisterDatasource("oci_database_management_managed_database_user_data_access_container", tf_database_management.DatabaseManagementManagedDatabaseUserDataAccessContainerDataSource())
	RegisterDatasource("oci_database_management_managed_database_user_object_privilege", tf_database_management.DatabaseManagementManagedDatabaseUserObjectPrivilegeDataSource())
	RegisterDatasource("oci_database_management_managed_database_user_proxied_for_user", tf_database_management.DatabaseManagementManagedDatabaseUserProxiedForUserDataSource())
	RegisterDatasource("oci_database_management_managed_database_user_role", tf_database_management.DatabaseManagementManagedDatabaseUserRoleDataSource())
	RegisterDatasource("oci_database_management_managed_databases_asm_property", tf_database_management.DatabaseManagementManagedDatabasesAsmPropertyDataSource())
	RegisterDatasource("oci_database_management_managed_databases_database_parameter", tf_database_management.DatabaseManagementManagedDatabasesDatabaseParameterDataSource())
	RegisterDatasource("oci_database_management_managed_databases_user_proxy_user", tf_database_management.DatabaseManagementManagedDatabasesUserProxyUserDataSource())
	RegisterDatasource("oci_database_management_managed_databases_user_system_privilege", tf_database_management.DatabaseManagementManagedDatabasesUserSystemPrivilegeDataSource())
	// database_migration service
	RegisterDatasource("oci_database_migration_agent", tf_database_migration.DatabaseMigrationAgentDataSource())
	RegisterDatasource("oci_database_migration_agent_image", tf_database_migration.DatabaseMigrationAgentImageDataSource())
	RegisterDatasource("oci_database_migration_connection", tf_database_migration.DatabaseMigrationConnectionDataSource())
	RegisterDatasource("oci_database_migration_job", tf_database_migration.DatabaseMigrationJobDataSource())
	RegisterDatasource("oci_database_migration_job_advisor_report", tf_database_migration.DatabaseMigrationJobAdvisorReportDataSource())
	RegisterDatasource("oci_database_migration_job_output", tf_database_migration.DatabaseMigrationJobOutputDataSource())
	RegisterDatasource("oci_database_migration_migration", tf_database_migration.DatabaseMigrationMigrationDataSource())
	RegisterDatasource("oci_database_migration_migration_object_type", tf_database_migration.DatabaseMigrationMigrationObjectTypeDataSource())
	// database_tools service
	RegisterDatasource("oci_database_tools_database_tools_connection", tf_database_tools.DatabaseToolsDatabaseToolsConnectionDataSource())
	RegisterDatasource("oci_database_tools_database_tools_endpoint_service", tf_database_tools.DatabaseToolsDatabaseToolsEndpointServiceDataSource())
	RegisterDatasource("oci_database_tools_database_tools_private_endpoint", tf_database_tools.DatabaseToolsDatabaseToolsPrivateEndpointDataSource())
	// datacatalog service
	RegisterDatasource("oci_datacatalog_catalog", tf_datacatalog.DatacatalogCatalogDataSource())
	RegisterDatasource("oci_datacatalog_catalog_private_endpoint", tf_datacatalog.DatacatalogCatalogPrivateEndpointDataSource())
	RegisterDatasource("oci_datacatalog_catalog_type", tf_datacatalog.DatacatalogCatalogTypeDataSource())
	RegisterDatasource("oci_datacatalog_connection", tf_datacatalog.DatacatalogConnectionDataSource())
	RegisterDatasource("oci_datacatalog_data_asset", tf_datacatalog.DatacatalogDataAssetDataSource())
	RegisterDatasource("oci_datacatalog_metastore", tf_datacatalog.DatacatalogMetastoreDataSource())
	// dataflow service
	RegisterDatasource("oci_dataflow_application", tf_dataflow.DataflowApplicationDataSource())
	RegisterDatasource("oci_dataflow_invoke_run", tf_dataflow.DataflowInvokeRunDataSource())
	RegisterDatasource("oci_dataflow_private_endpoint", tf_dataflow.DataflowPrivateEndpointDataSource())
	RegisterDatasource("oci_dataflow_run_log", tf_dataflow.DataflowRunLogDataSource())
	// dataintegration service
	RegisterDatasource("oci_dataintegration_workspace", tf_dataintegration.DataintegrationWorkspaceDataSource())
	// datascience service
	RegisterDatasource("oci_datascience_fast_launch_job_config", tf_datascience.DatascienceFastLaunchJobConfigDataSource())
	RegisterDatasource("oci_datascience_job", tf_datascience.DatascienceJobDataSource())
	RegisterDatasource("oci_datascience_job_run", tf_datascience.DatascienceJobRunDataSource())
	RegisterDatasource("oci_datascience_job_shape", tf_datascience.DatascienceJobShapeDataSource())
	RegisterDatasource("oci_datascience_model", tf_datascience.DatascienceModelDataSource())
	RegisterDatasource("oci_datascience_model_deployment", tf_datascience.DatascienceModelDeploymentDataSource())
	RegisterDatasource("oci_datascience_model_deployment_shape", tf_datascience.DatascienceModelDeploymentShapeDataSource())
	RegisterDatasource("oci_datascience_model_provenance", tf_datascience.DatascienceModelProvenanceDataSource())
	RegisterDatasource("oci_datascience_notebook_session", tf_datascience.DatascienceNotebookSessionDataSource())
	RegisterDatasource("oci_datascience_notebook_session_shape", tf_datascience.DatascienceNotebookSessionShapeDataSource())
	RegisterDatasource("oci_datascience_project", tf_datascience.DatascienceProjectDataSource())
	// devops service
	RegisterDatasource("oci_devops_build_pipeline", tf_devops.DevopsBuildPipelineDataSource())
	RegisterDatasource("oci_devops_build_pipeline_stage", tf_devops.DevopsBuildPipelineStageDataSource())
	RegisterDatasource("oci_devops_build_run", tf_devops.DevopsBuildRunDataSource())
	RegisterDatasource("oci_devops_connection", tf_devops.DevopsConnectionDataSource())
	RegisterDatasource("oci_devops_deploy_artifact", tf_devops.DevopsDeployArtifactDataSource())
	RegisterDatasource("oci_devops_deploy_environment", tf_devops.DevopsDeployEnvironmentDataSource())
	RegisterDatasource("oci_devops_deploy_pipeline", tf_devops.DevopsDeployPipelineDataSource())
	RegisterDatasource("oci_devops_deploy_stage", tf_devops.DevopsDeployStageDataSource())
	RegisterDatasource("oci_devops_deployment", tf_devops.DevopsDeploymentDataSource())
	RegisterDatasource("oci_devops_project", tf_devops.DevopsProjectDataSource())
	RegisterDatasource("oci_devops_repository", tf_devops.DevopsRepositoryDataSource())
	RegisterDatasource("oci_devops_repository_archive_content", tf_devops.DevopsRepositoryArchiveContentDataSource())
	RegisterDatasource("oci_devops_repository_author", tf_devops.DevopsRepositoryAuthorDataSource())
	RegisterDatasource("oci_devops_repository_commit", tf_devops.DevopsRepositoryCommitDataSource())
	RegisterDatasource("oci_devops_repository_diff", tf_devops.DevopsRepositoryDiffDataSource())
	RegisterDatasource("oci_devops_repository_diff", tf_devops.DevopsRepositoryDiffDataSource())
	RegisterDatasource("oci_devops_repository_file_diff", tf_devops.DevopsRepositoryFileDiffDataSource())
	RegisterDatasource("oci_devops_repository_file_line", tf_devops.DevopsRepositoryFileLineDataSource())
	RegisterDatasource("oci_devops_repository_file_line", tf_devops.DevopsRepositoryFileLineDataSource())
	RegisterDatasource("oci_devops_repository_mirror_record", tf_devops.DevopsRepositoryMirrorRecordDataSource())
	RegisterDatasource("oci_devops_repository_object", tf_devops.DevopsRepositoryObjectDataSource())
	RegisterDatasource("oci_devops_repository_object_content", tf_devops.DevopsRepositoryObjectContentDataSource())
	RegisterDatasource("oci_devops_repository_path", tf_devops.DevopsRepositoryPathDataSource())
	RegisterDatasource("oci_devops_repository_ref", tf_devops.DevopsRepositoryRefDataSource())
	RegisterDatasource("oci_devops_trigger", tf_devops.DevopsTriggerDataSource())
	// dns service
	RegisterDatasource("oci_dns_record", tf_dns.DnsRecordDataSource())
	RegisterDatasource("oci_dns_resolver", tf_dns.DnsResolverDataSource())
	RegisterDatasource("oci_dns_resolver_endpoint", tf_dns.DnsResolverEndpointDataSource())
	RegisterDatasource("oci_dns_rrset", tf_dns.DnsRrsetDataSource())
	RegisterDatasource("oci_dns_steering_policy", tf_dns.DnsSteeringPolicyDataSource())
	RegisterDatasource("oci_dns_steering_policy_attachment", tf_dns.DnsSteeringPolicyAttachmentDataSource())
	RegisterDatasource("oci_dns_tsig_key", tf_dns.DnsTsigKeyDataSource())
	RegisterDatasource("oci_dns_view", tf_dns.DnsViewDataSource())
	RegisterDatasource("oci_dns_zone", tf_dns.DnsZoneDataSource())
	// email service
	RegisterDatasource("oci_email_dkim", tf_email.EmailDkimDataSource())
	RegisterDatasource("oci_email_email_domain", tf_email.EmailEmailDomainDataSource())
	RegisterDatasource("oci_email_sender", tf_email.EmailSenderDataSource())
	RegisterDatasource("oci_email_suppression", tf_email.EmailSuppressionDataSource())
	// events service
	RegisterDatasource("oci_events_rule", tf_events.EventsRuleDataSource())
	// file_storage service
	RegisterDatasource("oci_file_storage_export", tf_file_storage.FileStorageExportDataSource())
	RegisterDatasource("oci_file_storage_export_set", tf_file_storage.FileStorageExportSetDataSource())
	RegisterDatasource("oci_file_storage_file_system", tf_file_storage.FileStorageFileSystemDataSource())
	RegisterDatasource("oci_file_storage_mount_target", tf_file_storage.FileStorageMountTargetDataSource())
	RegisterDatasource("oci_file_storage_snapshot", tf_file_storage.FileStorageSnapshotDataSource())
	// functions service
	RegisterDatasource("oci_functions_application", tf_functions.FunctionsApplicationDataSource())
	RegisterDatasource("oci_functions_function", tf_functions.FunctionsFunctionDataSource())
	// generic_artifacts_content service
	RegisterDatasource("oci_generic_artifacts_content_generic_artifacts_content", tf_generic_artifacts_content.GenericArtifactsContentGenericArtifactsContentDataSource())
	// golden_gate service
	RegisterDatasource("oci_golden_gate_database_registration", tf_golden_gate.GoldenGateDatabaseRegistrationDataSource())
	RegisterDatasource("oci_golden_gate_deployment", tf_golden_gate.GoldenGateDeploymentDataSource())
	RegisterDatasource("oci_golden_gate_deployment_backup", tf_golden_gate.GoldenGateDeploymentBackupDataSource())
	RegisterDatasource("oci_golden_gate_deployment_upgrade", tf_golden_gate.GoldenGateDeploymentUpgradeDataSource())
	// health_checks service
	RegisterDatasource("oci_health_checks_http_monitor", tf_health_checks.HealthChecksHttpMonitorDataSource())
	RegisterDatasource("oci_health_checks_http_probe_result", tf_health_checks.HealthChecksHttpProbeResultDataSource())
	RegisterDatasource("oci_health_checks_ping_monitor", tf_health_checks.HealthChecksPingMonitorDataSource())
	RegisterDatasource("oci_health_checks_ping_probe_result", tf_health_checks.HealthChecksPingProbeResultDataSource())
	RegisterDatasource("oci_health_checks_vantage_point", tf_health_checks.HealthChecksVantagePointDataSource())
	// identity service
	RegisterDatasource("oci_identity_allowed_domain_license_type", tf_identity.IdentityAllowedDomainLicenseTypeDataSource())
	RegisterDatasource("oci_identity_api_key", tf_identity.IdentityApiKeyDataSource())
	RegisterDatasource("oci_identity_auth_token", tf_identity.IdentityAuthTokenDataSource())
	RegisterDatasource("oci_identity_authentication_policy", tf_identity.IdentityAuthenticationPolicyDataSource())
	RegisterDatasource("oci_identity_availability_domain", tf_identity.IdentityAvailabilityDomainDataSource())
	RegisterDatasource("oci_identity_compartment", tf_identity.IdentityCompartmentDataSource())
	RegisterDatasource("oci_identity_cost_tracking_tag", tf_identity.IdentityCostTrackingTagDataSource())
	RegisterDatasource("oci_identity_customer_secret_key", tf_identity.IdentityCustomerSecretKeyDataSource())
	RegisterDatasource("oci_identity_db_credential", tf_identity.IdentityDbCredentialDataSource())
	RegisterDatasource("oci_identity_domain", tf_identity.IdentityDomainDataSource())
	RegisterDatasource("oci_identity_dynamic_group", tf_identity.IdentityDynamicGroupDataSource())
	RegisterDatasource("oci_identity_fault_domain", tf_identity.IdentityFaultDomainDataSource())
	RegisterDatasource("oci_identity_group", tf_identity.IdentityGroupDataSource())
	RegisterDatasource("oci_identity_iam_work_request", tf_identity.IdentityIamWorkRequestDataSource())
	RegisterDatasource("oci_identity_iam_work_request_error", tf_identity.IdentityIamWorkRequestErrorDataSource())
	RegisterDatasource("oci_identity_iam_work_request_error", tf_identity.IdentityIamWorkRequestErrorDataSource())
	RegisterDatasource("oci_identity_iam_work_request_log", tf_identity.IdentityIamWorkRequestLogDataSource())
	RegisterDatasource("oci_identity_identity_provider", tf_identity.IdentityIdentityProviderDataSource())
	RegisterDatasource("oci_identity_identity_provider_group", tf_identity.IdentityIdentityProviderGroupDataSource())
	RegisterDatasource("oci_identity_idp_group_mapping", tf_identity.IdentityIdpGroupMappingDataSource())
	RegisterDatasource("oci_identity_network_source", tf_identity.IdentityNetworkSourceDataSource())
	RegisterDatasource("oci_identity_policy", tf_identity.IdentityPolicyDataSource())
	RegisterDatasource("oci_identity_region", tf_identity.IdentityRegionDataSource())
	RegisterDatasource("oci_identity_region_subscription", tf_identity.IdentityRegionSubscriptionDataSource())
	RegisterDatasource("oci_identity_smtp_credential", tf_identity.IdentitySmtpCredentialDataSource())
	RegisterDatasource("oci_identity_swift_password", tf_identity.IdentitySwiftPasswordDataSource())
	RegisterDatasource("oci_identity_tag", tf_identity.IdentityTagDataSource())
	RegisterDatasource("oci_identity_tag_default", tf_identity.IdentityTagDefaultDataSource())
	RegisterDatasource("oci_identity_tag_namespace", tf_identity.IdentityTagNamespaceDataSource())
	RegisterDatasource("oci_identity_tag_standard_tag_namespace_template", tf_identity.IdentityTagStandardTagNamespaceTemplateDataSource())
	RegisterDatasource("oci_identity_tag_standard_tag_namespace_template", tf_identity.IdentityTagStandardTagNamespaceTemplateDataSource())
	RegisterDatasource("oci_identity_tenancy", tf_identity.IdentityTenancyDataSource())
	RegisterDatasource("oci_identity_ui_password", tf_identity.IdentityUiPasswordDataSource())
	RegisterDatasource("oci_identity_user", tf_identity.IdentityUserDataSource())
	RegisterDatasource("oci_identity_user_group_membership", tf_identity.IdentityUserGroupMembershipDataSource())
	// identity_data_plane service
	// integration service
	RegisterDatasource("oci_integration_integration_instance", tf_integration.IntegrationIntegrationInstanceDataSource())
	// jms service
	RegisterDatasource("oci_jms_fleet", tf_jms.JmsFleetDataSource())
	RegisterDatasource("oci_jms_fleet_blocklist", tf_jms.JmsFleetBlocklistDataSource())
	RegisterDatasource("oci_jms_fleet_installation_site", tf_jms.JmsFleetInstallationSiteDataSource())
	RegisterDatasource("oci_jms_list_jre_usage", tf_jms.JmsListJreUsageDataSource())
	RegisterDatasource("oci_jms_summarize_resource_inventory", tf_jms.JmsSummarizeResourceInventoryDataSource())
	// kms service
	RegisterDatasource("oci_kms_decrypted_data", tf_kms.KmsDecryptedDataDataSource())
	RegisterDatasource("oci_kms_key", tf_kms.KmsKeyDataSource())
	RegisterDatasource("oci_kms_key_version", tf_kms.KmsKeyVersionDataSource())
	RegisterDatasource("oci_kms_replication_status", tf_kms.KmsReplicationStatusDataSource())
	RegisterDatasource("oci_kms_vault", tf_kms.KmsVaultDataSource())
	RegisterDatasource("oci_kms_vault_replica", tf_kms.KmsVaultReplicaDataSource())
	RegisterDatasource("oci_kms_vault_usage", tf_kms.KmsVaultUsageDataSource())
	// limits service
	RegisterDatasource("oci_limits_limit_definition", tf_limits.LimitsLimitDefinitionDataSource())
	RegisterDatasource("oci_limits_limit_value", tf_limits.LimitsLimitValueDataSource())
	RegisterDatasource("oci_limits_quota", tf_limits.LimitsQuotaDataSource())
	RegisterDatasource("oci_limits_resource_availability", tf_limits.LimitsResourceAvailabilityDataSource())
	RegisterDatasource("oci_limits_service", tf_limits.LimitsServiceDataSource())
	// load_balancer service
	RegisterDatasource("oci_load_balancer_backend", tf_load_balancer.LoadBalancerBackendDataSource())
	RegisterDatasource("oci_load_balancer_backend_health", tf_load_balancer.LoadBalancerBackendHealthDataSource())
	RegisterDatasource("oci_load_balancer_backend_set", tf_load_balancer.LoadBalancerBackendSetDataSource())
	RegisterDatasource("oci_load_balancer_backend_set_health", tf_load_balancer.LoadBalancerBackendSetHealthDataSource())
	RegisterDatasource("oci_load_balancer_certificate", tf_load_balancer.LoadBalancerCertificateDataSource())
	RegisterDatasource("oci_load_balancer_hostname", tf_load_balancer.LoadBalancerHostnameDataSource())
	RegisterDatasource("oci_load_balancer_listener_rule", tf_load_balancer.LoadBalancerListenerRuleDataSource())
	RegisterDatasource("oci_load_balancer_load_balancer", tf_load_balancer.LoadBalancerLoadBalancerDataSource())
	RegisterDatasource("oci_load_balancer_health", tf_load_balancer.LoadBalancerLoadBalancerHealthDataSource())
	RegisterDatasource("oci_load_balancer_load_balancer_policy", tf_load_balancer.LoadBalancerLoadBalancerPolicyDataSource())
	RegisterDatasource("oci_load_balancer_load_balancer_protocol", tf_load_balancer.LoadBalancerLoadBalancerProtocolDataSource())
	RegisterDatasource("oci_load_balancer_load_balancer_routing_policy", tf_load_balancer.LoadBalancerLoadBalancerRoutingPolicyDataSource())
	RegisterDatasource("oci_load_balancer_load_balancer_shape", tf_load_balancer.LoadBalancerLoadBalancerShapeDataSource())
	RegisterDatasource("oci_load_balancer_path_route_set", tf_load_balancer.LoadBalancerPathRouteSetDataSource())
	RegisterDatasource("oci_load_balancer_rule_set", tf_load_balancer.LoadBalancerRuleSetDataSource())
	RegisterDatasource("oci_load_balancer_ssl_cipher_suite", tf_load_balancer.LoadBalancerSslCipherSuiteDataSource())
	// log_analytics service
	RegisterDatasource("oci_log_analytics_log_analytics_categories_list", tf_log_analytics.LogAnalyticsLogAnalyticsCategoriesListDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_category", tf_log_analytics.LogAnalyticsLogAnalyticsCategoryDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_entities_summary", tf_log_analytics.LogAnalyticsLogAnalyticsEntitiesSummaryDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_entity", tf_log_analytics.LogAnalyticsLogAnalyticsEntityDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_entity_topology", tf_log_analytics.LogAnalyticsLogAnalyticsEntityTopologyDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_log_group", tf_log_analytics.LogAnalyticsLogAnalyticsLogGroupDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_log_groups_summary", tf_log_analytics.LogAnalyticsLogAnalyticsLogGroupsSummaryDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_object_collection_rule", tf_log_analytics.LogAnalyticsLogAnalyticsObjectCollectionRuleDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_preference", tf_log_analytics.LogAnalyticsLogAnalyticsPreferenceDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_resource_categories_list", tf_log_analytics.LogAnalyticsLogAnalyticsResourceCategoriesListDataSource())
	RegisterDatasource("oci_log_analytics_log_analytics_unprocessed_data_bucket", tf_log_analytics.LogAnalyticsLogAnalyticsUnprocessedDataBucketDataSource())
	RegisterDatasource("oci_log_analytics_log_sets_count", tf_log_analytics.LogAnalyticsLogSetsCountDataSource())
	RegisterDatasource("oci_log_analytics_namespace", tf_log_analytics.LogAnalyticsNamespaceDataSource())
	RegisterDatasource("oci_log_analytics_namespace_scheduled_task", tf_log_analytics.LogAnalyticsNamespaceScheduledTaskDataSource())
	// logging service
	RegisterDatasource("oci_logging_log", tf_logging.LoggingLogDataSource())
	RegisterDatasource("oci_logging_log_group", tf_logging.LoggingLogGroupDataSource())
	RegisterDatasource("oci_logging_log_saved_search", tf_logging.LoggingLogSavedSearchDataSource())
	RegisterDatasource("oci_logging_unified_agent_configuration", tf_logging.LoggingUnifiedAgentConfigurationDataSource())
	// management_agent service
	RegisterDatasource("oci_management_agent_management_agent", tf_management_agent.ManagementAgentManagementAgentDataSource())
	RegisterDatasource("oci_management_agent_management_agent_available_history", tf_management_agent.ManagementAgentManagementAgentAvailableHistoryDataSource())
	RegisterDatasource("oci_management_agent_management_agent_count", tf_management_agent.ManagementAgentManagementAgentCountDataSource())
	RegisterDatasource("oci_management_agent_management_agent_get_auto_upgradable_config", tf_management_agent.ManagementAgentManagementAgentGetAutoUpgradableConfigDataSource())
	RegisterDatasource("oci_management_agent_management_agent_image", tf_management_agent.ManagementAgentManagementAgentImageDataSource())
	RegisterDatasource("oci_management_agent_management_agent_install_key", tf_management_agent.ManagementAgentManagementAgentInstallKeyDataSource())
	RegisterDatasource("oci_management_agent_management_agent_plugin", tf_management_agent.ManagementAgentManagementAgentPluginDataSource())
	RegisterDatasource("oci_management_agent_management_agent_plugin_count", tf_management_agent.ManagementAgentManagementAgentPluginCountDataSource())
	// management_dashboard service
	RegisterDatasource("oci_management_dashboard_management_dashboards_export", tf_management_dashboard.ManagementDashboardManagementDashboardsExportDataSource())
	// marketplace service
	RegisterDatasource("oci_marketplace_accepted_agreement", tf_marketplace.MarketplaceAcceptedAgreementDataSource())
	RegisterDatasource("oci_marketplace_category", tf_marketplace.MarketplaceCategoryDataSource())
	RegisterDatasource("oci_marketplace_listing", tf_marketplace.MarketplaceListingDataSource())
	RegisterDatasource("oci_marketplace_listing_package", tf_marketplace.MarketplaceListingPackageDataSource())
	RegisterDatasource("oci_marketplace_listing_package_agreement", tf_marketplace.MarketplaceListingPackageAgreementDataSource())
	RegisterDatasource("oci_marketplace_listing_tax", tf_marketplace.MarketplaceListingTaxDataSource())
	RegisterDatasource("oci_marketplace_publication", tf_marketplace.MarketplacePublicationDataSource())
	RegisterDatasource("oci_marketplace_publication_package", tf_marketplace.MarketplacePublicationPackageDataSource())
	RegisterDatasource("oci_marketplace_publisher", tf_marketplace.MarketplacePublisherDataSource())
	// metering_computation service
	RegisterDatasource("oci_metering_computation_configuration", tf_metering_computation.MeteringComputationConfigurationDataSource())
	RegisterDatasource("oci_metering_computation_custom_table", tf_metering_computation.MeteringComputationCustomTableDataSource())
	RegisterDatasource("oci_metering_computation_query", tf_metering_computation.MeteringComputationQueryDataSource())
	// monitoring service
	RegisterDatasource("oci_monitoring_alarm", tf_monitoring.MonitoringAlarmDataSource())
	RegisterDatasource("oci_monitoring_alarm_history_collection", tf_monitoring.MonitoringAlarmHistoryCollectionDataSource())
	RegisterDatasource("oci_monitoring_alarm_status", tf_monitoring.MonitoringAlarmStatusDataSource())
	RegisterDatasource("oci_monitoring_metric", tf_monitoring.MonitoringMetricDataSource())
	RegisterDatasource("oci_monitoring_metric_data", tf_monitoring.MonitoringMetricDataDataSource())
	// mysql service
	RegisterDatasource("oci_mysql_analytics_cluster", tf_mysql.MysqlAnalyticsClusterDataSource())
	RegisterDatasource("oci_mysql_channel", tf_mysql.MysqlChannelDataSource())
	RegisterDatasource("oci_mysql_heat_wave_cluster", tf_mysql.MysqlHeatWaveClusterDataSource())
	RegisterDatasource("oci_mysql_mysql_backup", tf_mysql.MysqlMysqlBackupDataSource())
	RegisterDatasource("oci_mysql_mysql_configuration", tf_mysql.MysqlMysqlConfigurationDataSource())
	RegisterDatasource("oci_mysql_mysql_db_system", tf_mysql.MysqlMysqlDbSystemDataSource())
	RegisterDatasource("oci_mysql_mysql_version", tf_mysql.MysqlMysqlVersionDataSource())
	RegisterDatasource("oci_mysql_shape", tf_mysql.MysqlShapeDataSource())
	// network_load_balancer service
	RegisterDatasource("oci_network_load_balancer_backend", tf_network_load_balancer.NetworkLoadBalancerBackendDataSource())
	RegisterDatasource("oci_network_load_balancer_backend_health", tf_network_load_balancer.NetworkLoadBalancerBackendHealthDataSource())
	RegisterDatasource("oci_network_load_balancer_backend_set", tf_network_load_balancer.NetworkLoadBalancerBackendSetDataSource())
	RegisterDatasource("oci_network_load_balancer_backend_sets_health", tf_network_load_balancer.NetworkLoadBalancerBackendSetsHealthDataSource())
	RegisterDatasource("oci_network_load_balancer_backend_sets_health_checker", tf_network_load_balancer.NetworkLoadBalancerBackendSetsHealthCheckerDataSource())
	RegisterDatasource("oci_network_load_balancer_listener", tf_network_load_balancer.NetworkLoadBalancerListenerDataSource())
	RegisterDatasource("oci_network_load_balancer_network_load_balancer", tf_network_load_balancer.NetworkLoadBalancerNetworkLoadBalancerDataSource())
	RegisterDatasource("oci_network_load_balancer_network_load_balancer_health", tf_network_load_balancer.NetworkLoadBalancerNetworkLoadBalancerHealthDataSource())
	RegisterDatasource("oci_network_load_balancer_network_load_balancers_policy", tf_network_load_balancer.NetworkLoadBalancerNetworkLoadBalancersPolicyDataSource())
	RegisterDatasource("oci_network_load_balancer_network_load_balancers_protocol", tf_network_load_balancer.NetworkLoadBalancerNetworkLoadBalancersProtocolDataSource())
	// nosql service
	RegisterDatasource("oci_nosql_index", tf_nosql.NosqlIndexDataSource())
	RegisterDatasource("oci_nosql_table", tf_nosql.NosqlTableDataSource())
	// object_storage service
	RegisterDatasource("oci_objectstorage_bucket", tf_object_storage.ObjectStorageBucketDataSource())
	RegisterDatasource("oci_objectstorage_namespace", tf_object_storage.ObjectStorageNamespaceDataSource())
	RegisterDatasource("oci_objectstorage_object", tf_object_storage.ObjectStorageObjectDataSource())
	RegisterDatasource("oci_objectstorage_object_lifecycle_policy", tf_object_storage.ObjectStorageObjectLifecyclePolicyDataSource())
	RegisterDatasource("oci_objectstorage_object_version", tf_object_storage.ObjectStorageObjectVersionDataSource())
	RegisterDatasource("oci_objectstorage_preauthrequest", tf_object_storage.ObjectStoragePreauthenticatedRequestDataSource())
	RegisterDatasource("oci_objectstorage_replication_policy", tf_object_storage.ObjectStorageReplicationPolicyDataSource())
	RegisterDatasource("oci_objectstorage_replication_source", tf_object_storage.ObjectStorageReplicationSourceDataSource())
	// oce service
	RegisterDatasource("oci_oce_oce_instance", tf_oce.OceOceInstanceDataSource())
	// ocvp service
	RegisterDatasource("oci_ocvp_esxi_host", tf_ocvp.OcvpEsxiHostDataSource())
	RegisterDatasource("oci_ocvp_sddc", tf_ocvp.OcvpSddcDataSource())
	RegisterDatasource("oci_ocvp_supported_host_shape", tf_ocvp.OcvpSupportedHostShapeDataSource())
	RegisterDatasource("oci_ocvp_supported_sku", tf_ocvp.OcvpSupportedSkuDataSource())
	RegisterDatasource("oci_ocvp_supported_vmware_software_version", tf_ocvp.OcvpSupportedVmwareSoftwareVersionDataSource())
	// oda service
	RegisterDatasource("oci_oda_oda_instance", tf_oda.OdaOdaInstanceDataSource())
	// ons service
	RegisterDatasource("oci_ons_notification_topic", tf_ons.OnsNotificationTopicDataSource())
	RegisterDatasource("oci_ons_subscription", tf_ons.OnsSubscriptionDataSource())
	// operator_access_control service
	RegisterDatasource("oci_operator_access_control_access_request", tf_operator_access_control.OperatorAccessControlAccessRequestDataSource())
	RegisterDatasource("oci_operator_access_control_access_request_history", tf_operator_access_control.OperatorAccessControlAccessRequestHistoryDataSource())
	RegisterDatasource("oci_operator_access_control_operator_action", tf_operator_access_control.OperatorAccessControlOperatorActionDataSource())
	RegisterDatasource("oci_operator_access_control_operator_control", tf_operator_access_control.OperatorAccessControlOperatorControlDataSource())
	RegisterDatasource("oci_operator_access_control_operator_control_assignment", tf_operator_access_control.OperatorAccessControlOperatorControlAssignmentDataSource())
	// opsi service
	RegisterDatasource("oci_opsi_awr_hub", tf_opsi.OpsiAwrHubDataSource())
	RegisterDatasource("oci_opsi_awr_hub_awr_snapshot", tf_opsi.OpsiAwrHubAwrSnapshotDataSource())
	RegisterDatasource("oci_opsi_awr_hub_awr_sources_summary", tf_opsi.OpsiAwrHubAwrSourcesSummaryDataSource())
	RegisterDatasource("oci_opsi_database_insight", tf_opsi.OpsiDatabaseInsightDataSource())
	RegisterDatasource("oci_opsi_enterprise_manager_bridge", tf_opsi.OpsiEnterpriseManagerBridgeDataSource())
	RegisterDatasource("oci_opsi_exadata_insight", tf_opsi.OpsiExadataInsightDataSource())
	RegisterDatasource("oci_opsi_host_insight", tf_opsi.OpsiHostInsightDataSource())
	RegisterDatasource("oci_opsi_operations_insights_private_endpoint", tf_opsi.OpsiOperationsInsightsPrivateEndpointDataSource())
	RegisterDatasource("oci_opsi_operations_insights_warehouse", tf_opsi.OpsiOperationsInsightsWarehouseDataSource())
	RegisterDatasource("oci_opsi_operations_insights_warehouse_resource_usage_summary", tf_opsi.OpsiOperationsInsightsWarehouseResourceUsageSummaryDataSource())
	RegisterDatasource("oci_opsi_operations_insights_warehouse_user", tf_opsi.OpsiOperationsInsightsWarehouseUserDataSource())
	// optimizer service
	RegisterDatasource("oci_optimizer_category", tf_optimizer.OptimizerCategoryDataSource())
	RegisterDatasource("oci_optimizer_enrollment_status", tf_optimizer.OptimizerEnrollmentStatusDataSource())
	RegisterDatasource("oci_optimizer_history", tf_optimizer.OptimizerHistoryDataSource())
	RegisterDatasource("oci_optimizer_profile", tf_optimizer.OptimizerProfileDataSource())
	RegisterDatasource("oci_optimizer_profile_level", tf_optimizer.OptimizerProfileLevelDataSource())
	RegisterDatasource("oci_optimizer_recommendation", tf_optimizer.OptimizerRecommendationDataSource())
	RegisterDatasource("oci_optimizer_recommendation_strategy", tf_optimizer.OptimizerRecommendationStrategyDataSource())
	RegisterDatasource("oci_optimizer_resource_action", tf_optimizer.OptimizerResourceActionDataSource())
	// osmanagement service
	RegisterDatasource("oci_osmanagement_managed_instance", tf_osmanagement.OsmanagementManagedInstanceDataSource())
	RegisterDatasource("oci_osmanagement_managed_instance_event_report", tf_osmanagement.OsmanagementManagedInstanceEventReportDataSource())
	RegisterDatasource("oci_osmanagement_managed_instance_group", tf_osmanagement.OsmanagementManagedInstanceGroupDataSource())
	RegisterDatasource("oci_osmanagement_software_source", tf_osmanagement.OsmanagementSoftwareSourceDataSource())
	// osp_gateway service
	RegisterDatasource("oci_osp_gateway_invoice", tf_osp_gateway.OspGatewayInvoiceDataSource())
	RegisterDatasource("oci_osp_gateway_invoices_invoice_line", tf_osp_gateway.OspGatewayInvoicesInvoiceLineDataSource())
	RegisterDatasource("oci_osp_gateway_subscription", tf_osp_gateway.OspGatewaySubscriptionDataSource())
	// osub_billing_schedule service
	RegisterDatasource("oci_osub_billing_schedule_billing_schedule", tf_osub_billing_schedule.OsubBillingScheduleBillingScheduleDataSource())
	// osub_organization_subscription service
	RegisterDatasource("oci_osub_organization_subscription_organization_subscription", tf_osub_organization_subscription.OsubOrganizationSubscriptionOrganizationSubscriptionDataSource())
	// osub_subscription service
	RegisterDatasource("oci_osub_subscription_commitment", tf_osub_subscription.OsubSubscriptionCommitmentDataSource())
	RegisterDatasource("oci_osub_subscription_ratecard", tf_osub_subscription.OsubSubscriptionRatecardDataSource())
	RegisterDatasource("oci_osub_subscription_subscription", tf_osub_subscription.OsubSubscriptionSubscriptionDataSource())
	// osub_usage service
	RegisterDatasource("oci_osub_usage_computed_usage", tf_osub_usage.OsubUsageComputedUsageDataSource())
	RegisterDatasource("oci_osub_usage_computed_usage_aggregated", tf_osub_usage.OsubUsageComputedUsageAggregatedDataSource())
	// resourcemanager service
	RegisterDatasource("oci_resourcemanager_stack", tf_resourcemanager.ResourcemanagerStackDataSource())
	RegisterDatasource("oci_resourcemanager_stack_tf_state", tf_resourcemanager.ResourcemanagerStackTfStateDataSource())
	// sch service
	RegisterDatasource("oci_sch_service_connector", tf_sch.SchServiceConnectorDataSource())
	// secrets service
	RegisterDatasource("oci_secrets_secretbundle", tf_secrets.SecretsSecretbundleDataSource())
	RegisterDatasource("oci_secrets_secretbundle_version", tf_secrets.SecretsSecretbundleVersionDataSource())
	// service_catalog service
	RegisterDatasource("oci_service_catalog_private_application", tf_service_catalog.ServiceCatalogPrivateApplicationDataSource())
	RegisterDatasource("oci_service_catalog_private_application_package", tf_service_catalog.ServiceCatalogPrivateApplicationPackageDataSource())
	RegisterDatasource("oci_service_catalog_service_catalog", tf_service_catalog.ServiceCatalogServiceCatalogDataSource())
	RegisterDatasource("oci_service_catalog_service_catalog_association", tf_service_catalog.ServiceCatalogServiceCatalogAssociationDataSource())
	// service_manager_proxy service
	RegisterDatasource("oci_service_manager_proxy_service_environment", tf_service_manager_proxy.ServiceManagerProxyServiceEnvironmentDataSource())
	// streaming service
	RegisterDatasource("oci_streaming_connect_harness", tf_streaming.StreamingConnectHarnessDataSource())
	RegisterDatasource("oci_streaming_stream", tf_streaming.StreamingStreamDataSource())
	RegisterDatasource("oci_streaming_stream_pool", tf_streaming.StreamingStreamPoolDataSource())
	// usage_proxy service
	RegisterDatasource("oci_usage_proxy_subscription_product", tf_usage_proxy.UsageProxySubscriptionProductDataSource())
	RegisterDatasource("oci_usage_proxy_subscription_redeemable_user", tf_usage_proxy.UsageProxySubscriptionRedeemableUserDataSource())
	RegisterDatasource("oci_usage_proxy_subscription_reward", tf_usage_proxy.UsageProxySubscriptionRewardDataSource())
	// vault service
	RegisterDatasource("oci_vault_secret", tf_vault.VaultSecretDataSource())
	RegisterDatasource("oci_vault_secret_version", tf_vault.VaultSecretVersionDataSource())
	// visual_builder service
	RegisterDatasource("oci_visual_builder_vb_instance", tf_visual_builder.VisualBuilderVbInstanceDataSource())
	// vulnerability_scanning service
	RegisterDatasource("oci_vulnerability_scanning_container_scan_recipe", tf_vulnerability_scanning.VulnerabilityScanningContainerScanRecipeDataSource())
	RegisterDatasource("oci_vulnerability_scanning_container_scan_target", tf_vulnerability_scanning.VulnerabilityScanningContainerScanTargetDataSource())
	RegisterDatasource("oci_vulnerability_scanning_host_scan_recipe", tf_vulnerability_scanning.VulnerabilityScanningHostScanRecipeDataSource())
	RegisterDatasource("oci_vulnerability_scanning_host_scan_target", tf_vulnerability_scanning.VulnerabilityScanningHostScanTargetDataSource())
	// waa service
	RegisterDatasource("oci_waa_web_app_acceleration", tf_waa.WaaWebAppAccelerationDataSource())
	RegisterDatasource("oci_waa_web_app_acceleration_policy", tf_waa.WaaWebAppAccelerationPolicyDataSource())
	// waas service
	RegisterDatasource("oci_waas_address_list", tf_waas.WaasAddressListDataSource())
	RegisterDatasource("oci_waas_certificate", tf_waas.WaasCertificateDataSource())
	RegisterDatasource("oci_waas_custom_protection_rule", tf_waas.WaasCustomProtectionRuleDataSource())
	RegisterDatasource("oci_waas_edge_subnet", tf_waas.WaasEdgeSubnetDataSource())
	RegisterDatasource("oci_waas_http_redirect", tf_waas.WaasHttpRedirectDataSource())
	RegisterDatasource("oci_waas_protection_rule", tf_waas.WaasProtectionRuleDataSource())
	RegisterDatasource("oci_waas_waas_policy", tf_waas.WaasWaasPolicyDataSource())
	// waf service
	RegisterDatasource("oci_waf_network_address_list", tf_waf.WafNetworkAddressListDataSource())
	RegisterDatasource("oci_waf_protection_capability", tf_waf.WafProtectionCapabilityDataSource())
	RegisterDatasource("oci_waf_protection_capability_group_tag", tf_waf.WafProtectionCapabilityGroupTagDataSource())
	RegisterDatasource("oci_waf_web_app_firewall", tf_waf.WafWebAppFirewallDataSource())
	RegisterDatasource("oci_waf_web_app_firewall_policy", tf_waf.WafWebAppFirewallPolicyDataSource())
}

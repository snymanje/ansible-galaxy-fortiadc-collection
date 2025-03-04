## FortiADC Ansible Collection
***

The collection is the FortiADC Ansible Automation project. It includes the modules that are able to configure FortiADC OS features.

## Modules
The collection provides the following modules:


* `fadcos_admin` Configure FortiADC admin
* `fadcos_backup_config` Download FortiADC config file
* `fadcos_interfadce` Manage FortiADC network interface
* `fadcos_nat_pool` Configure NAT pool
* `fadcos_nat_pool_member` Configure NAT pool member 
* `fadcos_real_server` Configure real server 
* `fadcos_real_server_pool` Configure real server pool 
* `fadcos_real_server_pool_member` Configure real server pool member
* `fadcos_route_static` Configure static route
* `fadcos_system_control` Perform reboot/shutdown on FortiADC devices
* `fadcos_system_setting` Configure system setting
* `fadc_vdom` Manage FortiADC VDOM
* `fadcos_virtual_server_basic` Add a basic virtual server
* `fadcos_virtual_server` Configure virtual server
* `fadcos_application_profile` Configure an application profile
* `fadcos_cert_verify` Configure a certificate verification object
* `fadcos_client_ssl_profile` Configure a client SSL profile
* `fadcos_health_check` Configure an health check object
* `fadcos_local_cert_group` Configure a local certificate group
* `fadcos_real_server_ssl_profile` Configure a real server SSL profile
* `fadcos_system_ha` Configure FortiADC HA
* `fadcos_system_ha_remote_ip_monitor` Configure a HA remote IP monitor
* `fadcos_vm_license` Upload a license for FortiADC VM
* `fadcos_error_page` Upload FortiADC Error Page
* `fadcos_load_balance_content_routing` Configure Content Routing
* `fadcos_load_balance_content_routing_child_match_condition` Configure Content Routing Child Match Condition
* `fadcos_load_balance_method` Configure LB method of Application Resources
* `fadcos_load_balance_persistence` Configure load balance persistence of Application Resources
* `fadcos_load_balance_persistence_child_iso8583_bitmap` Configure ISO8583 Bitmap persistence rule
* `fadcos_load_balance_persistence_child_radius_attribute` Configure RADIUS Attribute persistence rule
* `fadcos_system_certificate_local` Generate certificate signing request of Local Certificate
* `fadcos_system_certificate_local_upload` Import Local Certificate
* `fadcos_system_snmp_community` Configure SNMP community settings of SNMPv1/v2
* `fadcos_system_snmp_community_child_host` Configure child host of SNMPv1/v2
* `fadcos_system_snmp_sysinfo` Configure SNMP System Information settings
* `fadcos_system_snmp_user` Configure SNMP community settings of SNMPv3
* `fadcos_system_snmp_user_child_host` Configure child host of SNMPv3
* `fadcos_system_time_ntp` Manage system time ntp
* `fadcos_system_vdom` Configure the parameters of each VDOM
* `fadcos_waf_adaptive_learning` Configure the WAF adaptive learning 
* `fadcos_waf_adaptive_learning_child_url_list` Configure the WAF adaptive learning entries' child url lists
* `fadcos_waf_advanced_protection` Configure the WAF advanced protection 
* `fadcos_waf_advanced_protection_child_rule` Configure the WAF advanced protection  entries' child url lists
* `fadcos_waf_allowed_origin` Configure the WAF allowed origin 
* `fadcos_waf_api_discovery` Configure the WAF API discovery 
* `fadcos_waf_api_discovery_child_security_rule`  Configure the child security rules of WAF API discovery entries
* `fadcos_waf_api_gateway_policy` Configure the WAF gateway policies
* `fadcos_waf_api_gateway_rule` Configure the WAF gateway rules
* `fadcos_waf_api_gateway_user` Configure the WAF gateway users
* `fadcos_waf_brute_force_login` Configure the WAF brute force login defense
* `fadcos_waf_brute_force_login_child_match_condition` Configure the WAF brute force login defense match condition
* `fadcos_waf_cookie_security` Configure the WAF cookie security 
* `fadcos_waf_cookie_security_child_cookie_list` Configure the WAF cookie security entries' cookie lists
* `fadcos_waf_cors_headers` Configure the WAF CORS headers 
* `fadcos_waf_cors_headers_child_list` Configure the WAF CORS headers 
* `fadcos_waf_cors_protection` Configure the WAF CORS Protections
* `fadcos_waf_cors_protection_rule_list` Configure the WAF CORS Protection Rule List
* `fadcos_waf_credential_stuffing_defense` Configure the WAF credential stuffing defense
* `fadcos_waf_csrf_protection` Configure the WAF CSRF Protections
* `fadcos_waf_csrf_protection_child_page_list` Configure the WAF CSRF Protections child page list
* `fadcos_waf_csrf_protection_child_url_list` Configure the WAF CSRF Protections child url list
* `fadcos_waf_data_leak_prevention` Configure the WAF data leak prevention
* `fadcos_waf_data_leak_prevention_child_rule` Configure the WAF data leak prevention child rule
* `fadcos_waf_data_leak_prevention_dictionary` Configure the WAF data leak prevention dictionary
* `fadcos_waf_data_leak_prevention_sensors` Configure the WAF data leak prevention sensors
* `fadcos_waf_file_restriction_rule` Configure the WAF file restriction rule
* `fadcos_waf_heuristic_sql_xss_injection_detection` Configure the WAF heuristic SQL XSS injection detection
* `fadcos_waf_hidden_field_rule` Configure the WAF hidden field rules
* `fadcos_waf_http_header_security` Configure the WAF HTTP header security
* `fadcos_waf_http_header_security_child_rule_list` Configure the WAF HTTP header security rule list
* `fadcos_waf_http_protocol_constraint` Configure the WAF HTTP protocol constraint
* `fadcos_waf_input_validation_policy` Configure the WAF input validation policy
* `fadcos_waf_json_validation_detection` Configure the WAF JSON validation detection
* `fadcos_waf_openapi_validation_detection` Configure the WAF OpenApi validation detection
* `fadcos_waf_parameter_validation_rule` Configure the WAF parameter validation rule
* `fadcos_waf_profile` Configure the WAF profile
* `fadcos_waf_sensitive_data_type` Configure the WAF sensitive data types 
* `fadcos_waf_url_protection` Configure the WAF url protection
* `fadcos_waf_web_attack_signature` Configure the WAF web attack signature
* `fadcos_waf_xml_validation_detection` Configure the WAF XML validation detection 

## Usage
This collection includes some playbooks for configuring ADC OS.
Here is a quick example:

Create the `hosts` inventory file
```
[fortiadc]
adc01 ansible_host=192.168.1.99 ansible_user="admin" ansible_password="password"

[fortiadc:vars]
ansible_network_os=fortinet.fortiadc.fadcos
ansible_httpapi_use_ssl=yes
ansible_httpapi_validate_certs=no
ansible_httpapi_port=443
```

Run the playbook:
```bash
ansible-playbook -i hosts fadcos_system_setting.yml
```

This operation will adjust system idle timeout.

For other playbooks, please make sure required settings are already done in ADC OS before running them.

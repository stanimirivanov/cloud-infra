locals {
  # Strip hyphens and uppercase letters to comply with OCI DNS label rules
  dns_prefix = replace(lower(var.project_prefix), "-", "")
}

# Virtual Cloud Network (VCN)
resource "oci_core_vcn" "oke_vcn" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.0.0.0/16"]
  display_name   = "${var.project_prefix}-oke-vcn"
  dns_label      = "${local.dns_prefix}vcn"
}

# Internet Gateway for public connectivity
resource "oci_core_internet_gateway" "ig" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  display_name   = "${var.project_prefix}-internet-gateway"
}

# Route Table routing Internet traffic through Internet Gateway
resource "oci_core_route_table" "rt" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  display_name   = "${var.project_prefix}-route-table"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.ig.id
  }
}

# Subnet 1: Kubernetes API Endpoint
resource "oci_core_subnet" "k8s_endpoint_subnet" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  cidr_block     = "10.0.0.0/28"
  display_name   = "${var.project_prefix}-k8s-endpoint-subnet"
  dns_label      = "${local.dns_prefix}endpoint"
  route_table_id = oci_core_route_table.rt.id
}

# Subnet 2: Worker Nodes Subnet
resource "oci_core_subnet" "node_subnet" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  cidr_block     = "10.0.10.0/24"
  display_name   = "${var.project_prefix}-node-subnet"
  dns_label      = "${local.dns_prefix}nodes"
  route_table_id = oci_core_route_table.rt.id
}

# Subnet 3: Pod Subnet (Required for OCI_VCN_IP_NATIVE CNI)
resource "oci_core_subnet" "pod_subnet" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  cidr_block     = "10.0.20.0/24"
  display_name   = "${var.project_prefix}-pod-subnet"
  dns_label      = "${local.dns_prefix}pods"
  route_table_id = oci_core_route_table.rt.id
}

# --- API Endpoint NSG ---
resource "oci_core_network_security_group" "api_endpoint_nsg" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  display_name   = "${var.project_prefix}-api-endpoint-nsg"
}

resource "oci_core_network_security_group_security_rule" "api_ingress_worker_6443" {
  network_security_group_id = oci_core_network_security_group.api_endpoint_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6" # TCP
  source                    = oci_core_subnet.node_subnet.cidr_block
  source_type               = "CIDR_BLOCK"
  tcp_options {
    destination_port_range {
      min = 6443
      max = 6443
    }
  }
}

resource "oci_core_network_security_group_security_rule" "api_ingress_worker_12250" {
  network_security_group_id = oci_core_network_security_group.api_endpoint_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6" # TCP
  source                    = oci_core_subnet.node_subnet.cidr_block
  source_type               = "CIDR_BLOCK"
  tcp_options {
    destination_port_range {
      min = 12250
      max = 12250
    }
  }
}

resource "oci_core_network_security_group_security_rule" "api_ingress_public_6443" {
  network_security_group_id = oci_core_network_security_group.api_endpoint_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6" # TCP
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"
  tcp_options {
    destination_port_range {
      min = 6443
      max = 6443
    }
  }
}

resource "oci_core_network_security_group_security_rule" "api_icmp_ingress" {
  network_security_group_id = oci_core_network_security_group.api_endpoint_nsg.id
  direction                 = "INGRESS"
  protocol                  = "1" # ICMP
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"
  icmp_options {
    type = 3
    code = 4
  }
}

resource "oci_core_network_security_group_security_rule" "api_egress_all" {
  network_security_group_id = oci_core_network_security_group.api_endpoint_nsg.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
}

# --- Worker Node NSG ---
resource "oci_core_network_security_group" "node_nsg" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.oke_vcn.id
  display_name   = "${var.project_prefix}-node-nsg"
}

resource "oci_core_network_security_group_security_rule" "node_ingress_self_all" {
  network_security_group_id = oci_core_network_security_group.node_nsg.id
  direction                 = "INGRESS"
  protocol                  = "all"
  source                    = oci_core_subnet.node_subnet.cidr_block
  source_type               = "CIDR_BLOCK"
}

resource "oci_core_network_security_group_security_rule" "node_ingress_api_10250" {
  network_security_group_id = oci_core_network_security_group.node_nsg.id
  direction                 = "INGRESS"
  protocol                  = "6" # TCP
  source                    = oci_core_subnet.k8s_endpoint_subnet.cidr_block
  source_type               = "CIDR_BLOCK"
  tcp_options {
    destination_port_range {
      min = 10250
      max = 10250
    }
  }
}

resource "oci_core_network_security_group_security_rule" "node_ingress_nodeports" {
  network_security_group_id = oci_core_network_security_group.node_nsg.id
  direction                 = "INGRESS"
  protocol                  = "all"
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"
}

resource "oci_core_network_security_group_security_rule" "node_icmp_ingress" {
  network_security_group_id = oci_core_network_security_group.node_nsg.id
  direction                 = "INGRESS"
  protocol                  = "1" # ICMP
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"
  icmp_options {
    type = 3
    code = 4
  }
}

resource "oci_core_network_security_group_security_rule" "node_egress_all" {
  network_security_group_id = oci_core_network_security_group.node_nsg.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
}
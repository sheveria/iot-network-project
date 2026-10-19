# v2: MikroTik CHR hubs, no DynamoDB/SQS. ONE region (repeat per region; GA is global, create once).
# GA (anycast) -> NLB (UDP 4500, and UDP 500 as a fallback) -> ASG of CHR hubs across 3 AZ -> TGW -> Palo Alto.
# Not applied/validated; review before use.

terraform {
  required_version = ">= 1.8" # cidrcontains()
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.70" }
    archive = { source = "hashicorp/archive", version = "~> 2.6" }
  }
}

variable "region"              { default = "eu-central-1" }
variable "account_id"          { type = string }
variable "vpc_id"              { type = string }
variable "vpc_cidr"            { default = "10.50.0.0/24" } # IoT edge VPC; must equal the real VPC CIDR (checked below)
variable "slots_per_az"        { default = 4 }         # max hubs per AZ; total = slots_per_az * AZ count
variable "hub_ami_id"          { type = string }       # golden CHR AMI (configs/hub-mikrotik/golden-ami.rsc)
variable "hub_instance_type"   { default = "c6in.large" }
variable "hub_count"           { default = 3 }       # fixed number of hubs (no autoscaling); <= slots
variable "zone_id"             { type = string }
variable "fqdn"                { default = "vpn.iot.example.com" }
variable "pool_supernet"       { default = "10.100.0.0/16" } # device (mode-config) addresses, NOT part of the VPC; /22 per slot -> up to 64 slots
variable "syslog_ip"           { type = string }       # SIEM collector
variable "pa_syslog_ip"        { type = string }       # Palo Alto interface with User-ID syslog listener
variable "vault_addr"          { type = string }
variable "enable_ike_500"      { default = true }    # also accept IKE on UDP 500 (devices that cannot start on 4500); they switch to 4500 via NAT-T
variable "crl_refresh_mode"    { default = "auto" }  # readd | import | auto (confirm in PoC)

locals {
  crl_url = "${var.vault_addr}/v1/pki_iot/crl" # DER CRL; hubs download it
}
variable "ros_tls_fingerprint" { type = string }       # sha256 of golden AMI REST cert

provider "aws" { region = var.region }

# Addressing plan (subnets and route tables are created in network.tf):
#   VPC 10.50.0.0/24, per AZ a /26: public /28, hub /28, inner /28, tgw /28; lambda /28s in 10.50.0.192/26
#   slot ENI IP  = inner subnet host 10 + slot number   (e.g. AZ-a inner 10.50.0.32/28 -> .42 .. .45)
#   slot pool    = /22 of pool_supernet, index = AZ index * slots_per_az + slot (AZ-a: 10.100.0.0/22 ..)
data "aws_vpc" "this" { id = var.vpc_id }

check "addressing" {
  assert {
    condition     = data.aws_vpc.this.cidr_block == var.vpc_cidr
    error_message = "vpc_cidr does not match the CIDR of vpc_id."
  }
  assert {
    condition     = !cidrcontains(var.vpc_cidr, cidrhost(var.pool_supernet, 0)) && !cidrcontains(var.pool_supernet, cidrhost(var.vpc_cidr, 0))
    error_message = "pool_supernet must not overlap the VPC CIDR (pool addresses are routed to slot ENIs, not local)."
  }
}

# ------------------------------------------------------------------ NLB
resource "aws_security_group" "nlb" {
  name   = "iot-ipsec-nlb"
  vpc_id = var.vpc_id
  ingress {
    description = "IKEv2 NAT-T"
    from_port   = 4500
    to_port     = 4500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  dynamic "ingress" {
    for_each = var.enable_ike_500 ? [500] : []
    content {
      description = "IKEv2 initial exchange (fallback, device then switches to 4500)"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_lb" "ipsec" {
  name                             = "iot-ipsec"
  load_balancer_type               = "network"
  internal                         = false
  subnets                          = local.public_subnet_ids
  security_groups                  = [aws_security_group.nlb.id]
  enable_cross_zone_load_balancing = true
}

resource "aws_lb_target_group" "nat_t" {
  name                   = "iot-ipsec-4500"
  port                   = 4500
  protocol               = "UDP"
  target_type            = "instance"
  vpc_id                 = var.vpc_id
  deregistration_delay   = 15
  connection_termination = true

  stickiness {
    enabled = true
    type    = "source_ip"
  }

  health_check {
    protocol            = "TCP"
    port                = "8080" # RouterOS www service, VPC-only
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "nat_t" {
  load_balancer_arn = aws_lb.ipsec.arn
  port              = 4500
  protocol          = "UDP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nat_t.arn
  }
}

# Fallback: IKE on UDP 500. Same hubs, same source_ip stickiness: a device that starts on 500 and
# then floats to 4500 (NAT-T) should stay on one hub. Confirm in the PoC.
resource "aws_lb_target_group" "ike" {
  count                  = var.enable_ike_500 ? 1 : 0
  name                   = "iot-ipsec-500"
  port                   = 500
  protocol               = "UDP"
  target_type            = "instance"
  vpc_id                 = var.vpc_id
  deregistration_delay   = 15
  connection_termination = true

  stickiness {
    enabled = true
    type    = "source_ip"
  }

  health_check {
    protocol            = "TCP"
    port                = "8080"
    interval            = 10
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_listener" "ike" {
  count             = var.enable_ike_500 ? 1 : 0
  load_balancer_arn = aws_lb.ipsec.arn
  port              = 500
  protocol          = "UDP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ike[0].arn
  }
}

# ------------------------------------------------------------------ Global Accelerator + DNS
resource "aws_globalaccelerator_accelerator" "iot" {
  name            = "iot-ipsec"
  ip_address_type = "IPV4"
  enabled         = true
}

resource "aws_globalaccelerator_listener" "nat_t" {
  accelerator_arn = aws_globalaccelerator_accelerator.iot.id
  protocol        = "UDP"
  client_affinity = "SOURCE_IP"
  port_range {
    from_port = 4500
    to_port   = 4500
  }
  dynamic "port_range" {
    for_each = var.enable_ike_500 ? [500] : []
    content {
      from_port = port_range.value
      to_port   = port_range.value
    }
  }
}

resource "aws_globalaccelerator_endpoint_group" "region" {
  listener_arn            = aws_globalaccelerator_listener.nat_t.id
  endpoint_group_region   = var.region
  traffic_dial_percentage = 100
  endpoint_configuration {
    endpoint_id                    = aws_lb.ipsec.arn # GA uses NLB target health
    weight                         = 100
    client_ip_preservation_enabled = true             # verify for NLB endpoints in your regions
  }
}

resource "aws_route53_record" "vpn" {
  zone_id = var.zone_id
  name    = var.fqdn
  type    = "A"
  alias {
    name                   = aws_globalaccelerator_accelerator.iot.dns_name
    zone_id                = aws_globalaccelerator_accelerator.iot.hosted_zone_id
    evaluate_target_health = false
  }
}

# ------------------------------------------------------------------ hub fleet
resource "aws_security_group" "lambda" {
  name   = "iot-ipsec-lambda"
  vpc_id = var.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "hub" {
  name   = "iot-ipsec-hub"
  vpc_id = var.vpc_id
  ingress {
    description = "NAT-T (client IP preserved by NLB)"
    from_port   = 4500
    to_port     = 4500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  dynamic "ingress" {
    for_each = var.enable_ike_500 ? [500] : []
    content {
      description = "IKE initial exchange (fallback, client IP preserved by NLB)"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  ingress {
    description = "NLB health check"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  ingress {
    description     = "RouterOS REST on ether1: golden AMI bootstrap only (hub.rsc then moves REST to ether2/slot SG)"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }
  # ether1 starts no connections: replies are allowed by connection tracking. VPC-only egress is
  # enough for the bootstrap (replies to Lambda); all hub-initiated traffic uses the slot ENI.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }
}

# ------------------------------------------------------------------ slot ENIs (fixed IPs)
# One ENI per slot: fixed IP (PA syslog sender), owns one /22 pool, static route pool -> ENI.
# A new hub attaches a free slot ENI of its AZ as ether2 (hub_lifecycle Lambda).
locals {
  slots = {
    for pair in setproduct(local.az_range, range(var.slots_per_az)) :
    format("%s-%02d", local.azs[pair[0]], pair[1]) => {
      subnet_id  = local.inner_subnet_ids[pair[0]]
      inner_cidr = local.subnet_cidrs.inner[pair[0]]
      ip         = cidrhost(local.subnet_cidrs.inner[pair[0]], 10 + pair[1])
      pool       = cidrsubnet(var.pool_supernet, 6, pair[0] * var.slots_per_az + pair[1])
    }
  }
  # every tgw route table gets a route for every slot pool (index keys: route table ids are unknown at plan)
  slot_routes = {
    for pair in setproduct(local.az_range, keys(local.slots)) :
    "${pair[0]}/${pair[1]}" => { rt = local.tgw_route_table_ids[pair[0]], slot = pair[1] }
  }
}

check "hub_count_fits_slots" {
  assert {
    condition     = var.hub_count + 1 <= length(local.slots)
    error_message = "hub_count + 1 must not exceed the number of slots (slots_per_az * AZ count)."
  }
}

resource "aws_security_group" "slot" {
  name   = "iot-ipsec-slot"
  vpc_id = var.vpc_id
  ingress {
    description = "return traffic from TGW / Palo Alto to device pools; REST from Lambda (10.50.0.192/26 is inside 10/8)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }
  egress {
    description = "device traffic and all hub service traffic (syslog, DNS, CRL, licence) via TGW / Palo Alto"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # internet (licence renewal) only passes if Palo Alto / central egress allows it
  }
}

resource "aws_network_interface" "slot" {
  for_each          = local.slots
  subnet_id         = each.value.subnet_id
  private_ips       = [each.value.ip]
  security_groups   = [aws_security_group.slot.id]
  source_dest_check = false
  description       = "IoT IPsec hub slot ${each.key} (pool ${each.value.pool})"
  tags = {
    Name             = "iot-slot-${each.key}"
    "iot:slot-group" = "iot-ipsec-hub"
    "iot:slot"       = each.key
    "iot:pool"       = each.value.pool
    "iot:inner-cidr" = each.value.inner_cidr
  }
  lifecycle {
    ignore_changes = [attachment] # attached/detached at runtime by hub_lifecycle
  }
}

# Static return routes: pool -> slot ENI (never changed at runtime; blackhole while slot is free)
resource "aws_route" "slot_pool" {
  for_each               = local.slot_routes
  route_table_id         = each.value.rt
  destination_cidr_block = local.slots[each.value.slot].pool
  network_interface_id   = aws_network_interface.slot[each.value.slot].id
}

resource "aws_launch_template" "hub" {
  name_prefix            = "iot-ipsec-hub-"
  image_id               = var.hub_ami_id
  instance_type          = var.hub_instance_type
  vpc_security_group_ids = [aws_security_group.hub.id]
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_autoscaling_group" "hub" {
  name                      = "iot-ipsec-hub"
  # Fixed size: ASG only replaces failed hubs (ELB health). Change hub_count to scale manually.
  # max = hub_count + 1 lets instance refresh launch a replacement before terminating.
  min_size                  = var.hub_count
  max_size                  = var.hub_count + 1
  desired_capacity          = var.hub_count
  vpc_zone_identifier       = local.hub_subnet_ids
  target_group_arns         = concat([aws_lb_target_group.nat_t.arn], aws_lb_target_group.ike[*].arn)
  health_check_type         = "ELB"
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.hub.id
    version = "$Latest"
  }

  initial_lifecycle_hook {
    name                 = "provision"
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"
    default_result       = "ABANDON"
    heartbeat_timeout    = 900 # lambda runs serially (concurrency 1)
  }
  initial_lifecycle_hook {
    name                 = "release-slot"
    lifecycle_transition = "autoscaling:EC2_INSTANCE_TERMINATING"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 300
  }
}

# TGW side (in TGW module): static route var.pool_supernet -> this VPC attachment.

# ------------------------------------------------------------------ automation
data "archive_file" "automation" {
  type        = "zip"
  output_path = "${path.module}/build/automation.zip"
  source {
    content  = file("${path.module}/../automation/common.py")
    filename = "common.py"
  }
  source {
    content  = file("${path.module}/../automation/hub_lifecycle.py")
    filename = "hub_lifecycle.py"
  }
  source {
    content  = file("${path.module}/../automation/session_sync.py")
    filename = "session_sync.py"
  }
  source {
    content  = file("${path.module}/../configs/hub-mikrotik/hub.rsc")
    filename = "hub.rsc"
  }
}

resource "aws_secretsmanager_secret" "ros" { name = "iot/ros-provisioner" } # {"user","password"}

data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "hub_lifecycle" {
  name               = "iot-hub-lifecycle" # bound in Vault auth/aws/role/hub-provisioner
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

resource "aws_iam_role" "session_sync" {
  name               = "iot-session-sync"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

resource "aws_iam_role_policy_attachment" "vpc_access" {
  for_each   = { a = aws_iam_role.hub_lifecycle.name, b = aws_iam_role.session_sync.name }
  role       = each.value
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

data "aws_iam_policy_document" "hub_lifecycle" {
  statement {
    actions   = ["ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSubnets"]
    resources = ["*"]
  }
  # Attach/detach needs permission on both the slot ENI and the hub instance
  statement {
    actions   = ["ec2:AttachNetworkInterface", "ec2:DetachNetworkInterface"]
    resources = ["arn:aws:ec2:${var.region}:${var.account_id}:network-interface/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/iot:slot-group"
      values   = ["iot-ipsec-hub"]
    }
  }
  statement {
    actions   = ["ec2:AttachNetworkInterface", "ec2:DetachNetworkInterface", "ec2:CreateTags"]
    resources = ["arn:aws:ec2:${var.region}:${var.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/aws:autoscaling:groupName"
      values   = ["iot-ipsec-hub"]
    }
  }
  statement {
    actions   = ["autoscaling:CompleteLifecycleAction"]
    resources = [aws_autoscaling_group.hub.arn]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.ros.arn]
  }
  statement {
    actions   = ["ssm:GetParameter"] # current revoked list for a new hub
    resources = ["arn:aws:ssm:${var.region}:${var.account_id}:parameter/iot/revoked-recent"]
  }
}

data "aws_iam_policy_document" "session_sync" {
  statement {
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.ros.arn]
  }
  statement {
    actions   = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = ["arn:aws:ssm:${var.region}:${var.account_id}:parameter/iot/revoked-recent"]
  }
}

resource "aws_iam_role_policy" "hub_lifecycle" {
  role   = aws_iam_role.hub_lifecycle.id
  policy = data.aws_iam_policy_document.hub_lifecycle.json
}

resource "aws_iam_role_policy" "session_sync" {
  role   = aws_iam_role.session_sync.id
  policy = data.aws_iam_policy_document.session_sync.json
}

locals {
  common_env = {
    HUB_ASG             = "iot-ipsec-hub"
    ROS_SECRET          = aws_secretsmanager_secret.ros.name
    ROS_TLS_FINGERPRINT = var.ros_tls_fingerprint
  }
}

resource "aws_lambda_function" "hub_lifecycle" {
  function_name                  = "iot-hub-lifecycle"
  role                           = aws_iam_role.hub_lifecycle.arn
  runtime                        = "python3.12"
  handler                        = "hub_lifecycle.handler"
  filename                       = data.archive_file.automation.output_path
  source_code_hash               = data.archive_file.automation.output_base64sha256
  timeout                        = 600
  reserved_concurrent_executions = 1 # serialises slot claims
  vpc_config {
    subnet_ids         = local.lambda_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }
  environment {
    variables = merge(local.common_env, {
      SLOT_GROUP   = "iot-ipsec-hub"
      HUB_FQDN     = var.fqdn
      VPC_CIDR     = var.vpc_cidr
      SYSLOG_IP    = var.syslog_ip
      PA_SYSLOG_IP = var.pa_syslog_ip
      CRL_URL      = local.crl_url
      VAULT_ADDR   = var.vault_addr
      VAULT_ROLE   = "hub-provisioner"
    })
  }
}

# Revocation only: invoked by vault/device-cert.sh revoke (lambda:InvokeFunction for operators).
resource "aws_lambda_function" "session_sync" {
  function_name                  = "iot-session-sync"
  role                           = aws_iam_role.session_sync.arn
  runtime                        = "python3.12"
  handler                        = "session_sync.handler"
  filename                       = data.archive_file.automation.output_path
  source_code_hash               = data.archive_file.automation.output_base64sha256
  timeout                        = 120 # per hub: CRL refresh wait up to 2 x CRL_WAIT_S, hubs in parallel
  reserved_concurrent_executions = 1 # serialises updates of the revoked list
  vpc_config {
    subnet_ids         = local.lambda_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }
  environment {
    variables = merge(local.common_env, {
      DEVICE_DOMAIN    = "iot.example.com"
      REVOKED_HOLD_H   = "72" # > Vault CRL expiry (48h)
      CRL_URL          = local.crl_url
      CRL_PEM_URL      = "${local.crl_url}/pem"
      CRL_REFRESH_MODE = var.crl_refresh_mode
      CRL_WAIT_S       = "20"
    })
  }
}

resource "aws_cloudwatch_event_rule" "lifecycle" {
  name = "iot-hub-lifecycle"
  event_pattern = jsonencode({
    source      = ["aws.autoscaling"]
    detail-type = ["EC2 Instance-launch Lifecycle Action", "EC2 Instance-terminate Lifecycle Action"]
    detail      = { AutoScalingGroupName = [aws_autoscaling_group.hub.name] }
  })
}

resource "aws_cloudwatch_event_target" "lifecycle" {
  rule = aws_cloudwatch_event_rule.lifecycle.name
  arn  = aws_lambda_function.hub_lifecycle.arn
}

resource "aws_lambda_permission" "lifecycle" {
  statement_id  = "events-lifecycle"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.hub_lifecycle.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lifecycle.arn
}

output "accelerator_ips" { value = aws_globalaccelerator_accelerator.iot.ip_sets[0].ip_addresses }
output "nlb_dns"         { value = aws_lb.ipsec.dns_name }

# Register these IPs once in Palo Alto: Device > User Identification > Server Monitoring
# (type Syslog Sender). Allow UDP 514 from them to var.pa_syslog_ip.
output "slot_syslog_senders" {
  value = { for k, s in local.slots : k => { ip = s.ip, pool = s.pool } }
}

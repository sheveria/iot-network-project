# Subnets, route tables and TGW attachment of the IoT edge VPC (the VPC itself exists: var.vpc_id).
#
# VPC 10.50.0.0/24 (var.vpc_cidr), per AZ i a /26 block (cidrsubnet(vpc, 2, i)), inside it four /28:
#   0 public  NLB
#   1 hub     CHR primary ENI (ether1), DHCP: only IKE from the NLB and the NLB health check
#   2 inner   CHR slot ENIs (ether2), fixed IPs host 10..10+slots_per_az-1: device traffic AND all
#             hub service traffic (REST from Lambda, syslog, DNS, CRL, licence); default -> TGW
#   3 tgw     TGW attachment ENIs; its route table carries the static "pool /22 -> slot ENI" routes
# The 4th /26 block (index 3) holds one /28 per AZ for the automation Lambdas.
#
#                 AZ-a            AZ-b             AZ-c
#   public        10.50.0.0/28    10.50.0.64/28    10.50.0.128/28
#   hub           10.50.0.16/28   10.50.0.80/28    10.50.0.144/28
#   inner         10.50.0.32/28   10.50.0.96/28    10.50.0.160/28
#   tgw           10.50.0.48/28   10.50.0.112/28   10.50.0.176/28
#   lambda        10.50.0.192/28  10.50.0.208/28   10.50.0.224/28
#
# The device pool (var.pool_supernet) is NOT in the VPC: it is reached only through routes.

variable "az_count" {
  default = 3
  validation {
    condition     = var.az_count >= 1 && var.az_count <= 3
    error_message = "az_count must be 1..3: the 4th /26 of the VPC holds the Lambda subnets."
  }
}
variable "tgw_id"         { type = string } # Transit Gateway shared with the Palo Alto inspection VPC
variable "igw_id"         { type = string } # internet gateway of the VPC (NLB subnets)
variable "nat_gateway_id" { type = string } # egress for hubs (CHR licence, updates) and Lambdas

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs      = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  az_range = range(var.az_count)

  az_block = [for i in local.az_range : cidrsubnet(var.vpc_cidr, 2, i)] # /26 per AZ
  subnet_cidrs = {
    public = [for i in local.az_range : cidrsubnet(local.az_block[i], 2, 0)]
    hub    = [for i in local.az_range : cidrsubnet(local.az_block[i], 2, 1)]
    inner  = [for i in local.az_range : cidrsubnet(local.az_block[i], 2, 2)]
    tgw    = [for i in local.az_range : cidrsubnet(local.az_block[i], 2, 3)]
    lambda = [for i in local.az_range : cidrsubnet(cidrsubnet(var.vpc_cidr, 2, 3), 2, i)]
  }

  # one subnet per AZ and kind, same AZ order everywhere
  subnet_ids = {
    for kind, _ in local.subnet_cidrs : kind => [for i in local.az_range : aws_subnet.this["${kind}-${i}"].id]
  }
  public_subnet_ids = local.subnet_ids.public
  hub_subnet_ids    = local.subnet_ids.hub
  inner_subnet_ids  = local.subnet_ids.inner
  lambda_subnet_ids = local.subnet_ids.lambda
  # route tables that must send pool traffic back to the slot ENIs (see aws_route.slot_pool)
  tgw_route_table_ids = [for i in local.az_range : aws_route_table.tgw[i].id]
}

resource "aws_subnet" "this" {
  for_each = merge([
    for kind, cidrs in local.subnet_cidrs : {
      for i in local.az_range : "${kind}-${i}" => { kind = kind, az = local.azs[i], cidr = cidrs[i] }
    }
  ]...)
  vpc_id            = var.vpc_id
  availability_zone = each.value.az
  cidr_block        = each.value.cidr
  tags              = { Name = "iot-${each.value.kind}-${each.value.az}", "iot:kind" = each.value.kind }
}

# ------------------------------------------------------------------ route tables
resource "aws_route_table" "public" {
  vpc_id = var.vpc_id
  tags   = { Name = "iot-public" }
}
resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = var.igw_id
}

# hub (ether1): carries only IKE in and the NLB health check. All hub service traffic (REST, syslog,
# CRL, DNS, licence) uses ether2 / the inner subnet, so there is NO 10.0.0.0/8 -> TGW route here.
# The default route to the NAT gateway is kept only for replies to internet clients; remove it once
# the PoC confirms that NLB replies work without it.
resource "aws_route_table" "hub" {
  vpc_id = var.vpc_id
  tags   = { Name = "iot-hub" }
}
resource "aws_route" "hub_default" {
  route_table_id         = aws_route_table.hub.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.nat_gateway_id
}

# Lambdas: internet via NAT, platform/Vault (10.0.0.0/8) via TGW
resource "aws_route_table" "lambda" {
  vpc_id = var.vpc_id
  tags   = { Name = "iot-lambda" }
}
resource "aws_route" "lambda_default" {
  route_table_id         = aws_route_table.lambda.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = var.nat_gateway_id
}
resource "aws_route" "lambda_internal" {
  route_table_id         = aws_route_table.lambda.id
  destination_cidr_block = "10.0.0.0/8"
  transit_gateway_id     = var.tgw_id
  depends_on             = [aws_ec2_transit_gateway_vpc_attachment.this]
}

# inner (ether2): everything leaves via TGW -> Palo Alto
resource "aws_route_table" "inner" {
  vpc_id = var.vpc_id
  tags   = { Name = "iot-inner" }
}
resource "aws_route" "inner_default" {
  route_table_id         = aws_route_table.inner.id
  destination_cidr_block = "0.0.0.0/0"
  transit_gateway_id     = var.tgw_id
  depends_on             = [aws_ec2_transit_gateway_vpc_attachment.this]
}

# tgw subnets: one table per AZ; pool -> slot ENI routes are added in edge.tf (aws_route.slot_pool)
resource "aws_route_table" "tgw" {
  count  = var.az_count
  vpc_id = var.vpc_id
  tags   = { Name = "iot-tgw-${local.azs[count.index]}" }
}

resource "aws_route_table_association" "public" {
  count          = var.az_count
  subnet_id      = local.subnet_ids.public[count.index]
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "hub" {
  count          = var.az_count
  subnet_id      = local.subnet_ids.hub[count.index]
  route_table_id = aws_route_table.hub.id
}
resource "aws_route_table_association" "lambda" {
  count          = var.az_count
  subnet_id      = local.subnet_ids.lambda[count.index]
  route_table_id = aws_route_table.lambda.id
}
resource "aws_route_table_association" "inner" {
  count          = var.az_count
  subnet_id      = local.subnet_ids.inner[count.index]
  route_table_id = aws_route_table.inner.id
}
resource "aws_route_table_association" "tgw" {
  count          = var.az_count
  subnet_id      = local.subnet_ids.tgw[count.index]
  route_table_id = aws_route_table.tgw[count.index].id
}

# ------------------------------------------------------------------ TGW attachment
# Association with the right TGW route table and the static route var.pool_supernet -> this
# attachment are done in the TGW module (it knows the Palo Alto inspection routing).
resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  transit_gateway_id = var.tgw_id
  vpc_id             = var.vpc_id
  subnet_ids         = local.subnet_ids.tgw
  tags               = { Name = "iot-edge" }

  # associations/propagation belong to the TGW module
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false
}

output "subnet_cidrs"          { value = local.subnet_cidrs }
output "tgw_attachment_id"     { value = aws_ec2_transit_gateway_vpc_attachment.this.id }

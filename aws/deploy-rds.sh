#!/bin/bash

# Deploy Vulnerable RDS Infrastructure for Security Testing
# WARNING: This creates intentionally vulnerable resources!

set -e

STACK_NAME="vulnerable-rds-stack"
REGION="us-east-1"
TEMPLATE_FILE="rds-infrastructure.yaml"

echo "🔓 Deploying Vulnerable RDS Infrastructure for Security Testing"
echo "============================================================="
echo "⚠️  WARNING: This creates INTENTIONALLY VULNERABLE resources!"
echo "   - Use ONLY in isolated test environments"
echo "   - Do NOT use in production"
echo "   - Remember to delete resources after testing"
echo ""

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found. Please install AWS CLI first."
    exit 1
fi

# Check if template file exists
if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "❌ Template file $TEMPLATE_FILE not found."
    exit 1
fi

# Get VPC and Subnet information
echo "📋 Getting VPC and Subnet information..."
VPC_ID=$(aws ec2 describe-vpcs --query 'Vpcs[?IsDefault==`true`].VpcId' --output text --region $REGION)
if [ -z "$VPC_ID" ]; then
    echo "❌ No default VPC found. Please specify VPC ID manually."
    exit 1
fi

SUBNET_IDS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[].SubnetId' --output text --region $REGION | tr '\t' ',')
if [ -z "$SUBNET_IDS" ]; then
    echo "❌ No subnets found in VPC $VPC_ID."
    exit 1
fi

echo "✅ Found VPC: $VPC_ID"
echo "✅ Found Subnets: $SUBNET_IDS"

# Ask for confirmation
echo ""
read -p "⚠️  Are you sure you want to deploy VULNERABLE RDS resources? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "❌ Deployment cancelled."
    exit 1
fi

echo ""
echo "🚀 Deploying CloudFormation stack..."

# Deploy the stack
aws cloudformation deploy \
    --template-file "$TEMPLATE_FILE" \
    --stack-name "$STACK_NAME" \
    --parameter-overrides \
        VpcId="$VPC_ID" \
        SubnetIds="$SUBNET_IDS" \
    --capabilities CAPABILITY_IAM \
    --region "$REGION" \
    --tags \
        Purpose=security-testing \
        Warning=VULNERABLE-DO-NOT-USE-IN-PRODUCTION \
        CreatedBy=vulnerable-webapp

if [ $? -eq 0 ]; then
    echo "✅ Stack deployed successfully!"
    
    # Get outputs
    echo ""
    echo "📋 Stack Outputs:"
    aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue,Description]' \
        --output table
    
    # Get RDS endpoint for .env file
    RDS_ENDPOINT=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`RDSEndpoint`].OutputValue' \
        --output text)
    
    RDS_PORT=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`RDSPort`].OutputValue' \
        --output text)
    
    echo ""
    echo "🔧 Update your .env file with these values:"
    echo "USE_RDS=true"
    echo "RDS_ENDPOINT=$RDS_ENDPOINT"
    echo "RDS_PORT=$RDS_PORT"
    echo "RDS_USERNAME=admin"
    echo "RDS_PASSWORD=VulnerablePassword123"
    echo "RDS_DB_NAME=vulnerable_db"
    
    echo ""
    echo "⚠️  SECURITY WARNINGS FOR THIS RDS INSTANCE:"
    echo "   ❌ Publicly accessible from internet"
    echo "   ❌ Weak password (VulnerablePassword123)"
    echo "   ❌ No encryption at rest"
    echo "   ❌ No automated backups"
    echo "   ❌ No deletion protection"
    echo "   ❌ Overly permissive security group (0.0.0.0/0)"
    echo "   ❌ Single AZ deployment"
    echo "   ❌ General query logging enabled"
    
    echo ""
    echo "🎯 RDS Security Testing Capabilities:"
    echo "   ✅ Brute force attack simulation"
    echo "   ✅ SQL injection mass queries"
    echo "   ✅ Connection exhaustion attacks"
    echo "   ✅ Performance impact simulation"
    echo "   ✅ CloudWatch monitoring and alerting"
    echo "   ✅ Comprehensive logging (error, general, slow-query)"
    
    echo ""
    echo "🧹 Remember to delete resources when done:"
    echo "   aws cloudformation delete-stack --stack-name $STACK_NAME --region $REGION"
    
else
    echo "❌ Stack deployment failed!"
    exit 1
fi
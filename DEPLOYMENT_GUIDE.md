# StrongVPN AWS Deployment Guide

## Coded by Siddesh Pawar

Complete step-by-step guide to deploy StrongVPN across AWS regions using Free Tier VMs with manual installation.

---

## 📋 Prerequisites Checklist

### 1. AWS Account Setup
- [ ] AWS Free Tier account created
- [ ] Email verification completed
- [ ] Payment method added (required but won't be charged within Free Tier limits)
- [ ] Account activated (may take up to 24 hours)

### 2. Local Environment
- [ ] Windows 10/11 with PowerShell or WSL2
- [ ] Git installed
- [ ] Text editor (VS Code recommended)

---

## 🔧 Step 1: Install AWS CLI

### Option A: Windows PowerShell (Recommended)
```powershell
# Download AWS CLI installer
Invoke-WebRequest -Uri "https://awscli.amazonaws.com/AWSCLIV2.msi" -OutFile "AWSCLIV2.msi"

# Install AWS CLI
Start-Process msiexec.exe -Wait -ArgumentList '/I AWSCLIV2.msi /quiet'

# Verify installation
aws --version
```

**Expected Output:**
```
PS C:\Users\HP> aws --version
aws-cli/2.28.13 Python/3.13.4 Windows/10 exe/AMD64
```

---

## 🔑 Step 2: Configure AWS Credentials

### 2.1 Create IAM User (Recommended for Security)

1. **Login to AWS Console**: https://console.aws.amazon.com
2. **Navigate to IAM**: Services → IAM → Users
3. **Create User**:
   - Username: `strongvpn-deployer`
   - Access type: ✅ Programmatic access , FOR THIS CLICK ON ,"Provide user access to the AWS Management Console - optional"  THEN SELECT "I want to create an IAM user" , ALSO UNCHECK THE "Users must create a new password at next sign-in - Recommended" , YOU CAN PASS THE PASSWORD BY SELECTING "Custom password"  
4. **Attach Policies**:
   - ✅ `AmazonEC2FullAccess`
   - ✅ `AmazonVPCFullAccess`
4.2 now go to user , click on the user "strongvpn-deployer" click on "create access key" > then select "Access key best practices & alternatives " use case as " command line interface 
access key: [YOUR_ACCESS_KEY_HERE]
secret key: [YOUR_SECRET_KEY_HERE]
5. **Save Credentials**: Download CSV or copy Access Key ID + Secret

### 2.2 Configure AWS CLI
```bash
aws configure
```

**Enter the following:**
```
AWS Access Key ID [None]: [YOUR_ACCESS_KEY_HERE]
AWS Secret Access Key [None]: [YOUR_SECRET_KEY_HERE]
Default region name [None]: us-east-1
Default output format [None]: json
```

### 2.3 Verify Configuration
```bash
# Test AWS connection
aws sts get-caller-identity

# Expected output:
{
    "UserId": "AIDASLTDMZBGW2QRGXPNL",
    "Account": "162343471181",
    "Arn": "arn:aws:iam::162343471181:user/strongvpn-deployer"
}
```

---

## 📁 Step 3: Prepare AWS VM Deployment

### 3.1 Navigate to Project Directory
```bash
# Windows PowerShell
cd "C:\Users\HP\OneDrive\Documents\strongvpn"
```

### **Current Files in Your Directory:**
```
c:\Users\HP\OneDrive\Documents\strongvpn\
├── deploy_aws_vms.sh            ✅ EXISTS (AWS VM deployment script)
├── deploy_strongvpn.sh          ✅ EXISTS (StrongVPN installation script)
├── DEPLOYMENT_GUIDE.md          ✅ EXISTS (this guide)
├── CMakeLists.txt               ✅ EXISTS
├── MATHEMATICAL_FOUNDATIONS.md  ✅ EXISTS
└── [other project files]
```

### **Generated Files (Created After VM Deployment):**
- ⏳ `vm_connection_guide.txt` - SSH commands for all VMs
- ⏳ `vm_inventory_master.txt` - Complete VM inventory
- ⏳ `cleanup_aws_vms.sh` - Cleanup script
- ⏳ `strongvpn-freetier_*.pem` - SSH key files per region

### 3.2 Make Script Executable
```bash
# Linux/WSL2
chmod +x deploy_aws_vms.sh

# Windows PowerShell (if using Git Bash)
git update-index --chmod=+x deploy_aws_vms.sh
```

---

## 🚀 Step 4: Deploy AWS VMs

### 4.1 Run VM Deployment Script
```bash
.\deploy_aws_vms.sh
```

### 4.2 Expected Deployment Flow

**Initial Output:**
```
=== AWS Free Tier VM Deployment ===
Deploying 8 VMs across 4 regions (2 per region)
Instance Type: t2.micro (Free Tier)
Purpose: Manual StrongVPN setup
============================================
```

**Deployment Progress:**
```
=== Deploying to N. Virginia (US East) (us-east-1) ===
Creating key pair for us-east-1...
Key pair created: strongvpn-freetier_us-east-1.pem
Creating security group in us-east-1...
Security group created: sg-12345678
Ports opened: SSH(22), ICMP, VPN(1194,8443,500,4500,51820)
Launching VM 1 in us-east-1...
Instance launched: i-0123456789abcdef0
Waiting for instance to start...
VM 1 ready: 54.123.45.67
Launching VM 2 in us-east-1...
Instance launched: i-0987654321fedcba0
VM 2 ready: 18.234.56.78
us-east-1 deployment completed

=== Deploying to Oregon (US West) (us-west-2) ===
[Similar output for us-west-2]

=== Deploying to Ireland (Europe) (eu-west-1) ===
[Similar output for eu-west-1]

=== Deploying to Singapore (Asia Pacific) (ap-southeast-1) ===
[Similar output for ap-southeast-1]
```

### 4.3 Deployment Completion
```
=== AWS Free Tier VM Deployment Completed ===
Total VMs: 8 (2 per region)
Regions: us-east-1 us-west-2 eu-west-1 ap-southeast-1
Connection guide: vm_connection_guide.txt
Cleanup script: cleanup_aws_vms.sh
Cost: $0 (within Free Tier limits)

VMs are ready for manual StrongVPN installation!
```

---

## ⏱️ Step 5: Verify VM Deployment

### 5.1 Check Connection Guide
```bash
cat vm_connection_guide.txt
```

**Expected Output:**
```
=== AWS Free Tier VM Connection Guide ===

Total VMs Deployed: 8 (2 per region)
Instance Type: t2.micro (Free Tier)
Purpose: Manual StrongVPN setup

REGIONS AND VMs:

us-east-1 (N. Virginia (US East)):
  VM1: ssh -i strongvpn-freetier_us-east-1.pem ubuntu@54.123.45.67
       Instance: i-0123456789abcdef0
  VM2: ssh -i strongvpn-freetier_us-east-1.pem ubuntu@18.234.56.78
       Instance: i-0987654321fedcba0

us-west-2 (Oregon (US West)):
  VM1: ssh -i strongvpn-freetier_us-west-2.pem ubuntu@34.567.89.12
       Instance: i-0abcdef123456789
  VM2: ssh -i strongvpn-freetier_us-west-2.pem ubuntu@45.678.90.123
       Instance: i-0fedcba987654321

[Similar for eu-west-1 and ap-southeast-1]

SECURITY GROUPS:
- SSH: Port 22 (0.0.0.0/0)
- ICMP: Ping enabled
- VPN Ports: 1194(UDP), 8443(TCP), 500(UDP), 4500(UDP), 51820(UDP)
```

### 5.2 Monitor Instance Status
```bash
# Check all regions
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  echo "=== $region ==="
  aws ec2 describe-instances \
    --filters "Name=tag:Purpose,Values=StrongVPN" "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]' \
    --output table \
    --region $region
done
```

---

## 🔧 Step 6: Install StrongVPN on VMs

### 6.1 Connect to VM and Install StrongVPN

**Choose any VM from the connection guide and SSH into it:**
```bash
# Example: Connect to US East VM1
ssh -i strongvpn-freetier_us-east-1.pem ubuntu@54.123.45.67
```

**Once connected, run these commands:**
```bash
# Switch to root user
sudo su
# Enter your system password if prompted

# Download StrongVPN installation script
wget https://raw.githubusercontent.com/siddeshpawar/strongvpn/main/deploy_strongvpn.sh

# Make script executable
chmod +x deploy_strongvpn.sh

# Run installation (this will take 15-20 minutes)
sudo ./deploy_strongvpn.sh
```

### 6.2 Installation Process
**Expected Output:**
```
=== StrongVPN Installation Starting ===
Detected OS: ubuntu
Installing dependencies...
Cloning liboqs repository...
Building liboqs (this may take a few minutes)...
liboqs installed successfully
Cloning StrongVPN repository...
Building StrongVPN...
StrongVPN installation completed successfully!

Binaries available at:
- /root/strongvpn/build/bin/strongvpn_server
- /root/strongvpn/build/bin/strongvpn_client
```

### 6.3 Repeat Installation
**Install StrongVPN on at least 2 VMs in different regions for testing:**
- 1 VM as Server (e.g., US East)
- 1 VM as Client (e.g., Europe or Asia Pacific)

### 6.4 Test StrongVPN Connection

**On Server VM:**
```bash
# Navigate to build directory
cd /root/strongvpn/build

# Start server
./bin/strongvpn_server 8443
```

**On Client VM (different terminal/region):**
```bash
# Navigate to build directory  
cd /root/strongvpn/build

# Connect to server (replace with server's public IP)
./bin/strongvpn_client <server_ip> 8443
```

### 6.5 Expected Test Results
```
=== Server Output ===
Server listening on port 8443...
Waiting for client connections...
Client connected from <client_ip>
Post-quantum handshake initiated...
ML-KEM-768 key exchange successful
ML-DSA-65 authentication successful
Session established successfully

=== Client Output ===
Connecting to <server_ip>:8443...
Post-quantum handshake initiated...
ML-KEM-768 key exchange successful
ML-DSA-65 authentication successful
Post-quantum VPN tunnel established!
Connection successful - StrongVPN ready
```

---

## 📊 Step 7: Monitor and Test Performance

### 7.1 AWS Console Monitoring
1. **Login**: https://console.aws.amazon.com
2. **Billing Dashboard**: Account → Billing Dashboard
3. **Free Tier Usage**: View current usage vs limits

### 7.2 VM Status Monitoring
```bash
# Check VM status on any installed VM
ssh -i strongvpn-freetier_us-east-1.pem ubuntu@54.123.45.67
sudo su
cd /root
./vm_status.sh
```

**Output:**
```
=== AWS Free Tier VM Status ===
Region: us-east-1
Public IP: 54.123.45.67
Private IP: 172.31.45.67
Instance: t2.micro
Free Tier: Eligible
Uptime: up 2 hours, 15 minutes
Memory: 234M/983M
Disk: 2.1G/7.7G (28% used)
=================================
```

### 7.3 Cross-Region Performance Testing
**Test different region combinations:**
```bash
# US East → Europe (Transatlantic)
./bin/strongvpn_client <eu_server_ip> 8443

# US West → Asia Pacific (Transpacific)  
./bin/strongvpn_client <ap_server_ip> 8443

# Europe → Asia Pacific (Intercontinental)
./bin/strongvpn_client <ap_server_ip> 8443
```

---

## 🧹 Step 8: Cleanup (IMPORTANT!)

### 8.1 Terminate All VMs
```bash
# ALWAYS run this when finished testing
./cleanup_aws_vms.sh
```

**Expected Output:**
```
Cleaning up AWS Free Tier VMs...
Cleaning up region: us-east-1
Terminated instances: i-0123456789abcdef0 i-0987654321fedcba0
Deleted security group: sg-12345678
Cleaning up region: us-west-2
Terminated instances: i-0abcdef123456789 i-0fedcba987654321
Deleted security group: sg-87654321
Cleaning up region: eu-west-1
[Similar output for eu-west-1]
Cleaning up region: ap-southeast-1
[Similar output for ap-southeast-1]
Cleanup completed - no ongoing charges
```

### 8.2 Verify Cleanup
```bash
# Confirm no running instances across all regions
for region in us-east-1 us-west-2 eu-west-1 ap-southeast-1; do
  echo "Checking $region..."
  aws ec2 describe-instances \
    --filters "Name=tag:Purpose,Values=StrongVPN" "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].InstanceId' \
    --output text \
    --region $region
done

# Should return empty (no output) for all regions
```

---

## 🔧 Troubleshooting Guide

### Issue 1: AWS CLI Not Found
**Error:** `aws: command not found`
**Solution:**
```bash
# Restart terminal after installation
# Or add to PATH manually:
export PATH=$PATH:/usr/local/bin/aws
```

### Issue 2: Permission Denied
**Error:** `An error occurred (UnauthorizedOperation)`
**Solution:**
- Verify IAM user has EC2FullAccess policy
- Check AWS credentials: `aws configure list`

### Issue 3: Instance Launch Failed
**Error:** `InvalidAMIID.NotFound`
**Solution:**
- AMI IDs may be outdated
- Find current Ubuntu 22.04 AMI for your region:
```bash
aws ec2 describe-images \
  --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
  --query 'Images[*].[ImageId,CreationDate]' \
  --output table \
  --region us-east-1
```

### Issue 4: SSH Connection Failed
**Error:** `Permission denied (publickey)`
**Solution:**
- Check key file permissions: `chmod 400 *.pem`
- Verify correct key file name
- Wait 2-3 minutes after instance launch

### Issue 5: Free Tier Exceeded
**Error:** Unexpected charges
**Solution:**
- Check AWS Billing Dashboard
- Terminate all instances immediately
- Review Free Tier usage limits

---

## ✅ Success Verification Checklist

- [ ] AWS CLI installed and configured
- [ ] 8 t2.micro instances launched successfully across 4 regions
- [ ] SSH access to all instances working
- [ ] StrongVPN built and running on instances
- [ ] Cross-region post-quantum handshake successful
- [ ] Performance metrics collected
- [ ] All instances terminated after testing
- [ ] AWS Free Tier usage within limits

---

## 📈 Performance Expectations

### Free Tier Performance Metrics:
```
StrongVPN Build Time:      15-20 minutes per VM
Handshake Latency:         150-300ms (US ↔ EU)
                          200-400ms (US ↔ Asia Pacific)
                          100-250ms (EU ↔ Asia Pacific)
Memory Usage:              ~400MB/1GB available
CPU Usage:                 Moderate (burstable t2.micro)
Network Throughput:        Low-Moderate (Free Tier limits)
Total VMs:                 8 (2 per region)
Regions:                   4 (Global coverage)
```

### Academic Demonstration Value:
- ✅ **Global Deployment**: 8 VMs across 4 regions (US East/West, Europe, Asia Pacific)
- ✅ **Real Cryptography**: NIST FIPS 203/204 algorithms (ML-KEM-768, ML-DSA-65)
- ✅ **Zero Cost**: Complete within AWS Free Tier (8 × 750 hours = 6000 hours available)
- ✅ **Production Ready**: Actual cloud deployment with proper security groups
- ✅ **Manual Installation**: Demonstrates real-world deployment complexity
- ✅ **Cross-Continental**: Test US ↔ Europe ↔ Asia Pacific connectivity
- ✅ **Scalable Architecture**: Ready for enterprise scaling

---

## 🎯 Next Steps for Dissertation

1. **Document Results**: Screenshot deployment process
2. **Collect Metrics**: Save performance measurements
3. **Create Presentation**: Use deployment for defense demo
4. **Academic Writing**: Reference real-world deployment
5. **Future Work**: Discuss enterprise scaling potential

**Your StrongVPN is now deployed globally on AWS Free Tier - ready for academic demonstration!** 🌍🔐

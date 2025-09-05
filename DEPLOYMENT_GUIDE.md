# 🚀 배포 가이드 - 취약한 웹 애플리케이션

## 📋 배포 개요

이 문서는 AWS 보안 테스트를 위한 취약한 웹 애플리케이션을 EC2 인스턴스에 배포하는 방법을 설명합니다.

## 🎯 배포 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                        AWS VPC                             │
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │   Public Subnet │    │        Private Subnet           │ │
│  │                 │    │                                 │ │
│  │  ┌───────────┐  │    │  ┌─────────────┐ ┌────────────┐ │ │
│  │  │    EC2    │  │    │  │    RDS      │ │ CloudWatch │ │ │
│  │  │Vulnerable │  │    │  │   MySQL     │ │   Logs     │ │ │
│  │  │  WebApp   │  │    │  │             │ │            │ │ │
│  │  └───────────┘  │    │  └─────────────┘ └────────────┘ │ │
│  └─────────────────┘    └─────────────────────────────────┘ │
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                    Security Services                   │ │
│  │  GuardDuty | CloudTrail | VPC Flow Logs | Config      │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ 사전 요구사항

### 1. AWS 계정 준비
- 전용 테스트 AWS 계정 (필수)
- 적절한 IAM 권한
- 결제 알림 설정

### 2. 로컬 환경
- AWS CLI v2 설치 및 구성
- SSH 키 페어 생성
- Git 클라이언트

## 📦 1단계: AWS 인프라 구성

### VPC 및 네트워크 설정
```bash
# CloudFormation으로 VPC 생성
cd aws/
aws cloudformation create-stack \
  --stack-name vulnerable-webapp-vpc \
  --template-body file://vpc-template.yaml \
  --parameters ParameterKey=ProjectName,ParameterValue=vulnerable-webapp
```

### 보안 그룹 생성
```bash
# 웹 애플리케이션용 보안 그룹
aws ec2 create-security-group \
  --group-name vulnerable-webapp-sg \
  --description "Security group for vulnerable webapp" \
  --vpc-id vpc-xxxxxxxxx

# 인바운드 규칙 추가
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 8000 \
  --cidr 0.0.0.0/0

aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr YOUR_IP/32
```

## 🖥️ 2단계: EC2 인스턴스 생성

### 인스턴스 시작
```bash
# Amazon Linux 2 인스턴스 생성
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --count 1 \
  --instance-type t3.medium \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxxx \
  --subnet-id subnet-xxxxxxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=vulnerable-webapp},{Key=Purpose,Value=security-testing}]'
```

### SSH 접속
```bash
ssh -i your-key.pem ec2-user@your-instance-ip
```

## 📥 3단계: 서버 환경 설정

### 시스템 업데이트 및 기본 패키지 설치
```bash
# 시스템 업데이트
sudo yum update -y

# 필수 패키지 설치
sudo yum install -y git curl wget htop mysql jq

# Python 3.9 설치
sudo yum install -y python3.9 python3.9-pip

# uv 패키지 매니저 설치
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

### MySQL 설치 및 구성 (로컬 테스트용)
```bash
# MySQL 8.0 설치
sudo yum install -y mysql-server mysql

# MySQL 서비스 시작
sudo systemctl start mysqld
sudo systemctl enable mysqld

# 보안 설정
sudo mysql_secure_installation
```

## 📂 4단계: 애플리케이션 배포

### 코드 다운로드
```bash
# 홈 디렉토리에 클론
cd ~
git clone <repository-url> vulnerable-webapp
cd vulnerable-webapp
```

### Python 환경 설정
```bash
# uv로 의존성 설치
uv sync

# 환경 변수 설정
cp .env.example .env
nano .env
```

### 환경 변수 구성 (.env)
```bash
# AWS 설정
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=ap-northeast-2

# 데이터베이스 설정
USE_RDS=false
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=vulnerable123
DB_NAME=vulnerable_db

# 애플리케이션 설정
DEBUG=false
LOG_LEVEL=INFO
JWT_SECRET=weak_secret_key_123
S3_BUCKET_NAME=your-test-bucket-name
```

### 데이터베이스 초기화
```bash
# MySQL 로그인 및 데이터베이스 생성
mysql -u root -p <<EOF
CREATE DATABASE vulnerable_db;
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'vulnerable123';
GRANT ALL PRIVILEGES ON vulnerable_db.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;
USE vulnerable_db;
SOURCE init_db.sql;
EOF
```

### 스크립트 권한 설정
```bash
chmod +x *.sh
```

## ⚡ 5단계: 애플리케이션 시작

### 수동 시작 (테스트용)
```bash
# 애플리케이션 시작
./start.sh

# 상태 확인
./status.sh

# 로그 확인
tail -f app.log
```

### 서비스 등록 (프로덕션용)
```bash
# systemd 서비스 파일 생성
sudo tee /etc/systemd/system/vulnerable-webapp.service > /dev/null <<EOF
[Unit]
Description=Vulnerable Web Application for Security Testing
After=network.target mysql.service

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/vulnerable-webapp
ExecStart=/home/ec2-user/.local/bin/uv run python main.py
Restart=always
RestartSec=10
Environment=PATH=/home/ec2-user/.local/bin:/usr/local/bin:/bin:/usr/bin

[Install]
WantedBy=multi-user.target
EOF

# 서비스 활성화
sudo systemctl daemon-reload
sudo systemctl enable vulnerable-webapp
sudo systemctl start vulnerable-webapp

# 서비스 상태 확인
sudo systemctl status vulnerable-webapp
```

## 🔒 6단계: AWS 보안 서비스 구성

### GuardDuty 활성화
```bash
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES
```

### CloudTrail 설정
```bash
# S3 버킷 생성
aws s3 mb s3://your-cloudtrail-logs-bucket

# CloudTrail 생성
aws cloudtrail create-trail \
  --name vulnerable-webapp-trail \
  --s3-bucket-name your-cloudtrail-logs-bucket \
  --include-global-service-events \
  --is-multi-region-trail

# CloudTrail 시작
aws cloudtrail start-logging \
  --name vulnerable-webapp-trail
```

### VPC Flow Logs 활성화
```bash
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-xxxxxxxxx \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name VPCFlowLogs
```

## 🔧 7단계: 모니터링 구성

### CloudWatch 대시보드 생성
```bash
# 대시보드 JSON 파일 생성
cat > dashboard.json <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/EC2", "CPUUtilization", "InstanceId", "i-xxxxxxxxx"]
        ],
        "period": 300,
        "stat": "Average",
        "region": "ap-northeast-2",
        "title": "EC2 CPU Utilization"
      }
    }
  ]
}
EOF

# 대시보드 생성
aws cloudwatch put-dashboard \
  --dashboard-name "VulnerableWebApp" \
  --dashboard-body file://dashboard.json
```

### 경보 설정
```bash
# CPU 사용률 경보
aws cloudwatch put-metric-alarm \
  --alarm-name "High-CPU-Usage" \
  --alarm-description "Alert when CPU exceeds 80%" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2
```

## ✅ 8단계: 배포 검증

### 연결 테스트
```bash
# 로컬에서 테스트
curl -s http://your-ec2-ip:8000/health | jq .

# API 문서 접근
curl -s http://your-ec2-ip:8000/docs
```

### 기본 취약점 테스트
```bash
# SQL 인젝션 테스트
curl "http://your-ec2-ip:8000/api/v1/users/search?q=test"

# SSRF 테스트
curl "http://your-ec2-ip:8000/api/v1/exploit/ssrf?url=http://httpbin.org/ip"

# 포트 스캔 테스트
curl -X POST "http://your-ec2-ip:8000/api/v1/exploit/port-scan?target=8.8.8.8&ports=80,443"
```

## 📊 운영 관리

### 로그 관리
```bash
# 애플리케이션 로그 확인
tail -f /home/ec2-user/vulnerable-webapp/app.log

# 시스템 로그
sudo journalctl -u vulnerable-webapp -f

# GuardDuty 결과 확인
aws guardduty get-findings \
  --detector-id your-detector-id
```

### 백업 및 복구
```bash
# 애플리케이션 백업
tar -czf vulnerable-webapp-backup.tar.gz vulnerable-webapp/

# 데이터베이스 백업
mysqldump -u root -p vulnerable_db > backup.sql
```

## 🧹 정리 절차

### 리소스 정리
```bash
# 애플리케이션 중지
./stop.sh
sudo systemctl stop vulnerable-webapp
sudo systemctl disable vulnerable-webapp

# AWS 리소스 삭제
aws ec2 terminate-instances --instance-ids i-xxxxxxxxx
aws cloudformation delete-stack --stack-name vulnerable-webapp-vpc
aws s3 rb s3://your-cloudtrail-logs-bucket --force
```

## 🚨 보안 고려사항

### 네트워크 보안
- 신뢰할 수 있는 IP에서만 접근 허용
- 불필요한 포트 차단
- WAF 구성 (선택사항)

### 접근 제어
- IAM 역할 최소 권한 원칙
- MFA 활성화
- 정기적인 키 로테이션

### 모니터링
- 실시간 로그 모니터링
- 비정상적인 트래픽 알림
- 비용 모니터링

## 📞 지원

문제가 발생한 경우:
1. 로그 파일 확인
2. AWS 서비스 상태 점검
3. 네트워크 연결 확인
4. IAM 권한 검증

---

**주의**: 이 애플리케이션은 보안 테스트 목적으로만 사용하세요. 프로덕션 환경에서는 절대 사용하지 마세요!
# 🔓 취약한 웹 애플리케이션 - 보안 테스트 가이드

## 📋 개요

AWS 보안 서비스(GuardDuty, CloudTrail, VPC Flow Logs, CloudWatch) 테스트를 위해 설계된 의도적으로 취약한 웹 애플리케이션입니다. 교육 및 보안 연구 목적으로만 사용하며, **절대 프로덕션 환경에서 사용하지 마세요**.

## ⚠️ 경고

**이 애플리케이션은 의도적인 보안 취약점을 포함하고 있습니다:**
- SQL 인젝션
- 서버 측 요청 위조 (SSRF)
- 명령어 인젝션
- 권한 상승
- 파일 탐색
- IDOR (Insecure Direct Object Reference)

**오직 격리된 테스트 환경에서만 사용하세요!**

## 🏗️ 아키텍처

```
vulnerable-webapp/
├── app/
│   ├── core/           # 설정 파일
│   ├── routers/        # API 라우터
│   ├── templates/      # HTML 템플릿
│   └── main.py         # FastAPI 메인 애플리케이션
├── aws/                # AWS 인프라 스크립트
├── scripts/            # 관리 스크립트
└── README.md
```

## 🚀 빠른 시작

### 1. 요구사항
- Python 3.9+
- [uv](https://github.com/astral-sh/uv) 패키지 매니저
- AWS 자격 증명 구성
- Docker (선택사항)

### 2. 설치 및 실행

```bash
# 프로젝트 클론
git clone <repository-url>
cd vulnerable-webapp

# 환경 설정
cp .env.example .env
# .env 파일을 AWS 자격 증명으로 편집

# 의존성 설치
uv sync

# 애플리케이션 시작
./start.sh

# 상태 확인
./status.sh
```

### 3. 접근 포인트
- **웹 인터페이스**: http://your-server-ip:8000
- **API 문서**: http://your-server-ip:8000/docs
- **상태 확인**: http://your-server-ip:8000/health

## 📊 취약점 카테고리

### 1. SQL 인젝션 (사용자 관리)
**위치**: `/api/v1/users/*`

```bash
# 인증 우회
curl -X POST "http://localhost:8000/api/v1/users/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\''--", "password": "anything"}'

# 데이터 추출
curl "http://localhost:8000/api/v1/users/search?q='\'' UNION SELECT username,password FROM users--"
```

**GuardDuty 탐지**: 데이터베이스 공격 패턴

### 2. 서버 측 요청 위조 (SSRF)
**위치**: `/api/v1/exploit/ssrf`

```bash
# AWS 메타데이터 서비스 접근
curl "http://localhost:8000/api/v1/exploit/ssrf?url=http://169.254.169.254/latest/meta-data/"

# 내부 서비스 스캔
curl "http://localhost:8000/api/v1/exploit/ssrf?url=http://internal-service:8080"
```

**GuardDuty 탐지**: UnauthorizedAPICall:EC2/MaliciousIPCaller

### 3. 명령어 인젝션
**위치**: `/api/v1/exploit/command-injection`

```bash
# 시스템 명령어 실행
curl "http://localhost:8000/api/v1/exploit/command-injection?cmd=whoami"

# 파일 목록 확인
curl "http://localhost:8000/api/v1/exploit/command-injection?cmd=ls -la"
```

**GuardDuty 탐지**: 의심스러운 명령어 실행

### 4. 권한 상승
**위치**: `/api/v1/admin/*`

#### IDOR - 사용자 정보 접근
```bash
# 다른 사용자 정보 접근
curl "http://localhost:8000/api/v1/admin/users?user_id=1"
```

#### sudo 권한 획득
```bash
# 약한 패스워드로 sudo 실행
curl -X POST "http://localhost:8000/api/v1/admin/sudo-command" \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami", "password": "password123"}'
```

#### 사용자 역할 변경
```bash
# 관리자 권한 승격
curl -X POST "http://localhost:8000/api/v1/admin/change-user-role" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 2, "new_role": "admin", "admin_key": "admin123"}'
```

### 5. 파일 작업
**위치**: `/api/v1/files/*`

```bash
# 디렉토리 탐색
curl "http://localhost:8000/api/v1/files/download?filename=../../etc/passwd"

# 대량 파일 업로드 (S3)
curl -X POST "http://localhost:8000/api/v1/files/bulk-upload?count=100"
```

**GuardDuty 탐지**: 의심스러운 파일 활동

### 6. 네트워크 정찰
**위치**: `/api/v1/exploit/*`

#### 포트 스캔
```bash
curl -X POST "http://localhost:8000/api/v1/exploit/port-scan?target=8.8.8.8&ports=22,80,443"
```

#### DNS 조회
```bash
curl "http://localhost:8000/api/v1/exploit/dns-lookup?domain=suspicious-domain.com"
```

**GuardDuty 탐지**: Recon:EC2/PortProbeUnprotectedPort

### 7. 암호화폐 채굴 시뮬레이션
```bash
# CPU 사용률 급증 시뮬레이션
curl -X POST "http://localhost:8000/api/v1/exploit/crypto-mining-sim?duration=60"
```

**GuardDuty 탐지**: CryptoCurrency:EC2/BitcoinTool.B

### 8. RDS 공격 시뮬레이션
**위치**: `/api/v1/rds/*`

```bash
# 무차별 대입 공격
curl -X POST "http://localhost:8000/api/v1/rds/brute-force-attack?target_user=admin&attempts=50"

# 대량 SQL 인젝션
curl -X POST "http://localhost:8000/api/v1/rds/sql-injection-mass-query?query_count=100"

# 연결 풀 고갈
curl -X POST "http://localhost:8000/api/v1/rds/connection-exhaustion?concurrent_connections=20"
```

## 🛠️ 관리 스크립트

### 애플리케이션 제어
```bash
# 시작
./start.sh

# 중지
./stop.sh

# 재시작
./restart.sh

# 상태 확인
./status.sh
```

### 로그 모니터링
```bash
# 실시간 로그
tail -f app.log

# 에러 로그만
grep ERROR app.log

# 보안 이벤트 로그
grep CRITICAL app.log
```

## 📈 AWS 서비스 모니터링

### GuardDuty 탐지 예상 항목
- **CryptoCurrency:EC2/BitcoinTool.B**: 암호화폐 채굴 활동
- **UnauthorizedAPICall:EC2/MaliciousIPCaller**: 메타데이터 서비스 접근
- **Recon:EC2/PortProbeUnprotectedPort**: 포트 스캔 활동
- **Trojan:EC2/DNSDataExfiltration**: DNS를 통한 데이터 유출

### CloudTrail 이벤트
- IAM 역할/정책 생성
- EC2 인스턴스 생성/종료
- S3 버킷 작업
- RDS 인스턴스 생성

### CloudWatch 메트릭
- CPU 사용률 급증
- 네트워크 트래픽 이상
- 데이터베이스 연결 수 증가
- 애플리케이션 에러율 증가

## 🔧 설정

### 환경 변수 (.env)
```bash
# AWS 설정
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=ap-northeast-2

# 데이터베이스 설정
USE_RDS=false
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=vulnerable123

# 애플리케이션 설정
DEBUG=true
LOG_LEVEL=DEBUG
S3_BUCKET_NAME=vulnerable-test-bucket
```

### AWS 권한 요구사항
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "ec2:*",
        "iam:*",
        "logs:*",
        "cloudtrail:*",
        "rds:*"
      ],
      "Resource": "*"
    }
  ]
}
```

## 🚨 보안 모범 사례 (테스트 전용)

### 1. 격리된 환경
- 전용 AWS 테스트 계정 사용
- 별도 VPC에 배포
- 인터넷에서 직접 접근 차단

### 2. 모니터링 설정
- GuardDuty 활성화
- CloudTrail 로깅 활성화
- VPC Flow Logs 활성화
- 청구 알림 설정

### 3. 정리 절차
- 테스트 완료 후 모든 리소스 삭제
- S3 버킷 정리
- 생성된 IAM 역할/정책 삭제

## 📚 문서 및 리소스

### API 문서
- Swagger UI: http://your-server-ip:8000/docs
- ReDoc: http://your-server-ip:8000/redoc

### 로그 레벨 설명
- **CRITICAL**: 심각한 보안 위협 (권한 상승, 중요 파일 접근)
- **WARNING**: 의심스러운 활동 (SQL 인젝션 시도, SSRF)
- **INFO**: 일반적인 작업 (정상 로그인, 파일 업로드)
- **DEBUG**: 상세한 디버그 정보

## 🔍 트러블슈팅

### 일반적인 문제

#### 1. 포트 8000 이미 사용 중
```bash
sudo lsof -i :8000
./stop.sh
./start.sh
```

#### 2. AWS 권한 오류
```bash
# AWS 자격 증명 확인
aws sts get-caller-identity

# 권한 테스트
aws s3 ls
aws ec2 describe-instances
```

#### 3. 데이터베이스 연결 실패
```bash
# MySQL 서비스 상태 확인
systemctl status mysql

# 연결 테스트
mysql -u root -p -h localhost
```

## 📞 지원 및 기여

### 이슈 리포팅
버그나 개선사항이 있으면 GitHub Issues를 통해 리포트해 주세요.

### 기여 가이드
1. 새로운 취약점 유형 추가
2. AWS 서비스 커버리지 개선
3. 로깅 및 모니터링 향상
4. 문서 개선

## ⚖️ 법적 고지

이 소프트웨어는 **교육 및 보안 연구 목적으로만** 설계되었습니다. 사용자는:

- 승인된 테스트 환경에서만 사용
- 관련 법률 및 규정 준수
- 악의적인 목적으로 사용 금지
- 모든 결과에 대한 책임 수용

**기억하세요**: 이 애플리케이션은 의도적으로 취약합니다. 절대 프로덕션에서 사용하지 마세요!

---

**해당 프로젝트는 보안 교육 목적으로 제작되었으며, 실제 공격에 사용해서는 안 됩니다.**
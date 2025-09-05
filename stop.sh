#!/bin/bash

# 취약한 웹 애플리케이션 중지 스크립트

APP_DIR="/home/ec2-user/bob-Damn/vulnerable-webapp"
PID_FILE="$APP_DIR/app.pid"

echo "취약한 웹 애플리케이션을 중지합니다..."

# PID 파일에서 프로세스 중지
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    echo "PID 파일에서 찾은 프로세스: $PID"
    
    if ps -p $PID > /dev/null 2>&1; then
        echo "프로세스 $PID 를 종료합니다..."
        kill $PID
        
        # 10초 대기 후 강제 종료 확인
        sleep 10
        
        if ps -p $PID > /dev/null 2>&1; then
            echo "정상 종료되지 않았습니다. 강제 종료합니다..."
            kill -9 $PID
            sleep 2
        fi
        
        if ! ps -p $PID > /dev/null 2>&1; then
            echo "✅ 프로세스가 성공적으로 종료되었습니다."
            rm -f "$PID_FILE"
        else
            echo "❌ 프로세스 종료에 실패했습니다."
        fi
    else
        echo "⚠️ PID $PID 프로세스가 실행되지 않고 있습니다."
        rm -f "$PID_FILE"
    fi
else
    echo "⚠️ PID 파일이 없습니다."
fi

# 포트 8000에서 실행 중인 모든 프로세스 확인 및 종료
echo ""
echo "포트 8000에서 실행 중인 프로세스 확인..."
PORT_PIDS=$(sudo lsof -ti :8000)

if [ -n "$PORT_PIDS" ]; then
    echo "포트 8000에서 실행 중인 프로세스들:"
    sudo lsof -i :8000
    echo ""
    
    for pid in $PORT_PIDS; do
        echo "프로세스 $pid 를 종료합니다..."
        kill $pid 2>/dev/null
        sleep 2
        
        if ps -p $pid > /dev/null 2>&1; then
            echo "강제 종료합니다: $pid"
            kill -9 $pid 2>/dev/null
        fi
    done
    
    sleep 2
    
    # 최종 확인
    REMAINING=$(sudo lsof -ti :8000)
    if [ -z "$REMAINING" ]; then
        echo "✅ 모든 프로세스가 성공적으로 종료되었습니다."
    else
        echo "❌ 일부 프로세스가 여전히 실행 중입니다:"
        sudo lsof -i :8000
    fi
else
    echo "✅ 포트 8000에서 실행 중인 프로세스가 없습니다."
fi

echo ""
echo "애플리케이션 중지 완료!"
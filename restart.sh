#!/bin/bash

# 취약한 웹 애플리케이션 재시작 스크립트

echo "🔄 취약한 웹 애플리케이션을 재시작합니다..."
echo ""

# 현재 애플리케이션 중지
echo "1️⃣ 애플리케이션 중지 중..."
./stop.sh

echo ""
echo "⏳ 5초 대기..."
sleep 5

echo ""
echo "2️⃣ 애플리케이션 시작 중..."
./start.sh

echo ""
echo "✅ 재시작 완료!"
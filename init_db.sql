-- 데이터베이스 생성
CREATE DATABASE IF NOT EXISTS vulnerable_db;
USE vulnerable_db;

-- users 테이블 생성
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 테스트용 초기 데이터 삽입
INSERT INTO users (username, password, email) VALUES 
('admin', MD5('admin123'), 'admin@vulnerable.com'),
('user1', MD5('password'), 'user1@test.com'),
('test', MD5('test123'), 'test@example.com'),
('guest', MD5('guest'), 'guest@vulnerable.com');

-- 인덱스 생성 (성능 테스트용)
CREATE INDEX idx_username ON users(username);
CREATE INDEX idx_email ON users(email);

SELECT 'Database and tables created successfully!' as status;
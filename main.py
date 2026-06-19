"""
Nginx 로그 분석 및 비정상 접근 탐지 API
"""

import json
import os
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Query


app = FastAPI(title="Nginx Security Analyzer API")


def env_int(name, default, minimum, maximum):
    value = os.getenv(name, str(default))

    try:
        parsed = int(value)
    except ValueError as error:
        raise RuntimeError(f"{name} must be an integer: {value}") from error

    if not minimum <= parsed <= maximum:
        raise RuntimeError(
            f"{name} must be between {minimum} and {maximum}: {parsed}"
        )

    return parsed


LOG_PATH = os.getenv("LOG_PATH", "/var/log/nginx/access.log")
DEFAULT_MAX_LINES = env_int("DEFAULT_MAX_LINES", 5000, 100, 100000)
DEFAULT_WINDOW_HOURS = env_int("DEFAULT_WINDOW_HOURS", 3, 1, 24)
API_PORT = env_int("API_PORT", 8000, 1, 65535)

LOG_TIME_PATTERN = re.compile(r"\[([^\]]+)\]")

SUSPICIOUS_PATTERNS = {
    "환경 파일 접근 시도": [
        r"\.env",
        r"config\.php",
        r"settings\.py",
    ],
    "관리자 페이지 스캔": [
        r"/wp-admin",
        r"/phpmyadmin",
        r"/admin",
        r"/manager",
    ],
    "SQL Injection 의심": [
        r"union\s+select",
        r"or\s+1\s*=\s*1",
        r"and\s+1\s*=\s*1",
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"information_schema",
    ],
    "경로 탐색 공격": [
        r"\.\./",
        r"\.\.\\",
        r"etc/passwd",
        r"windows/win\.ini",
    ],
    "XSS 의심": [
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
    ],
    "동적 스크립트 스캔": [
        r"\.php",
        r"\.jsp",
        r"\.asp",
        r"\.aspx",
    ],
}


def parse_log_time(line):
    match = LOG_TIME_PATTERN.search(line)
    if not match:
        return None

    try:
        return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def recent_lines(path, max_lines, hours, now=None):
    current_time = now or datetime.now().astimezone()
    cutoff_time = current_time - timedelta(hours=hours)
    lines = deque(maxlen=max_lines)

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            log_time = parse_log_time(line)
            if log_time and cutoff_time <= log_time <= current_time:
                lines.append(line)

    return list(lines)


def parse_ip(line):
    parts = line.split()
    if not parts:
        return "UNKNOWN"
    return parts[0]


def normalize_line(line):
    lower = line.lower()
    decoded = unquote(lower)
    return decoded


def detect_attack(line):
    normalized = normalize_line(line)
    detected = []

    for attack_name, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, normalized):
                detected.append(attack_name)
                break

    return detected


def calculate_risk(total_count, top_ip_count):
    if total_count >= 100 or top_ip_count >= 50:
        return "HIGH"
    if total_count >= 20 or top_ip_count >= 10:
        return "MEDIUM"
    if total_count > 0:
        return "LOW"
    return "NONE"


def analyze_log(log_path, max_lines, hours):
    lines = recent_lines(log_path, max_lines, hours)

    suspicious_logs = []
    ip_counter = Counter()
    attack_counter = Counter()
    ip_attack_map = defaultdict(Counter)

    for line in lines:
        attacks = detect_attack(line)

        if attacks:
            ip = parse_ip(line)
            ip_counter[ip] += 1

            for attack in attacks:
                attack_counter[attack] += 1
                ip_attack_map[ip][attack] += 1

            suspicious_logs.append(
                {
                    "ip": ip,
                    "attacks": attacks,
                    "raw": line.strip(),
                }
            )

    total_suspicious_count = len(suspicious_logs)
    top_ip_count = ip_counter.most_common(1)[0][1] if ip_counter else 0
    risk_level = calculate_risk(total_suspicious_count, top_ip_count)

    return {
        "riskLevel": risk_level,
        "analysisWindowHours": hours,
        "totalSuspiciousCount": total_suspicious_count,
        "analyzedLineCount": len(lines),
        "attackSummary": dict(attack_counter.most_common()),
        "topIps": [
            {
                "ip": ip,
                "count": count,
                "attackTypes": dict(ip_attack_map[ip].most_common()),
            }
            for ip, count in ip_counter.most_common(10)
        ],
        "samples": suspicious_logs[:20],
    }


@app.get("/")
def root():
    return {
        "message": "Nginx Security Analyzer API",
        "endpoints": [
            "/health",
            "/security/analyze",
        ],
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/security/analyze")
def analyze_security_log(
    hours: int = Query(default=DEFAULT_WINDOW_HOURS, ge=1, le=24),
    max_lines: int = Query(default=DEFAULT_MAX_LINES, ge=100, le=100000),
):
    try:
        return analyze_log(LOG_PATH, max_lines, hours)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Log file not found: {LOG_PATH}",
        )
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail=f"Permission denied: {LOG_PATH}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e),
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=API_PORT,
        reload=os.getenv("UVICORN_RELOAD", "false").lower() == "true",
    )

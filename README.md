# Nginx Security Analyzer

Nginx access log에서 최근 요청을 읽어 의심스러운 접근 패턴을 분석하는
FastAPI 서비스입니다.

## Docker Compose로 실행

Linux nginx 서버에서 프로젝트 디렉터리로 이동한 뒤 실행합니다.

```bash
cp .env.example .env
docker compose up -d --build
```

기본적으로 호스트의 `/var/log/nginx/access.log`를 컨테이너에 읽기
전용으로 연결합니다. 경로나 파일명이 다르면 `.env`를 수정합니다.

```env
NGINX_LOG_DIR=/var/log/nginx
NGINX_ACCESS_LOG=access.log
API_PORT=8000
DEFAULT_WINDOW_HOURS=3
DEFAULT_MAX_LINES=5000
```

## API 사용

상태 확인:

```bash
curl http://localhost:8000/health
```

기본 분석:

```bash
curl http://localhost:8000/security/analyze
```

최근 6시간, 최대 10,000줄 분석:

```bash
curl "http://localhost:8000/security/analyze?hours=6&max_lines=10000"
```

Swagger UI는 `http://localhost:8000/docs`에서 확인할 수 있습니다.

## Windows에서 샘플 로그로 테스트

현재 프로젝트의 `access.log`를 Docker Desktop에서 사용하려면 `.env`의
로그 디렉터리를 다음처럼 설정합니다.

```env
NGINX_LOG_DIR=.
NGINX_ACCESS_LOG=access.log
```

그다음 `docker-compose up -d --build`로 실행할 수 있습니다.

## 로그 권한

컨테이너는 로그 디렉터리를 읽기 전용으로 사용합니다. `403 Permission
denied`가 반환되면 호스트의 nginx 로그 파일 및 상위 디렉터리에 읽기
권한이 있는지 확인해야 합니다.

API 요청마다 로그 파일을 새로 열기 때문에 일반적인 nginx logrotate로
`access.log` 파일이 교체되어도 다음 요청부터 새 파일을 읽습니다.

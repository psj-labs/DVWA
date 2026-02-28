## 개요

- 본 실습은 DVWA(Damn Vulnerable Web Application) **Brute Force – Low 단계**에서 Burp Suite **Intruder 기능을 이용해 관리자(admin) 계정의 비밀번호를 무차별 대입 공격으로 찾아내는 과정**을 기록합니다.

## 패킷 캡처

- 로그인 화면에서 Burp Suite의 **Intercept를 ON**한 상태로  
- ID와 PW에 각각 `test / test`를 입력해 로그인 요청 패킷을 캡처합니다.

![burp_intercept](imgs/intercept%20on.png)

- Intercept 상태이기 때문에 브라우저는 다음 화면으로 이동하지 않으며
- 오른쪽 하단 Request 영역에 다음 파라미터를 포함한 요청이 확인됩니다.
```text
?username=test&password=test&Login=login
```

- 이는 사용자가 입력한 ID와 비밀번호가 서버로 전달되는 요청임을 의미합니다.  
- 해당 요청을 Burp Suite **Intruder로 전송합니다.**


## Intruder로 전송

Request → Pretty 영역에서 마우스 우클릭 후 **Send to Intruder**를 선택합니다.

![burp_intercept](imgs/send%20to%20intruder.png)

- Intruder 탭으로 이동하여 공격 세팅을 진행합니다.


## Payload 위치 설정

- Intruder 화면에서 공격 대상 파라미터의 위치를 지정합니다.

![burp_intercept](imgs/add%20payload%20position.png)

- **username 값은 `admin`으로 고정합니다.**
  - 공격 목적은 관리자(admin)의 비밀번호 탈취이기 때문입니다.
- `password=test` 중 **test 부분만 드래그 선택 후**
  - 우클릭 → **Add payload position**을 눌러 페이로드 위치로 설정합니다.

- 이 설정을 통해 공격 시 비밀번호 값만 순차적으로 바뀌며 요청이 반복 전송됩니다.


## Payload 등록

- Payload 탭에서 사용할 **비밀번호 후보 리스트를 등록합니다.**

- DVWA 리포지토리에 업로드해 둔 password payload 목록을 삽입합니다.

![burp_intercept](imgs/insert%20payload.png)

- 등록 완료 상태에서는 다수의 비밀번호 문자열들이 목록에 추가된 것이 확인됩니다.


## 공격 실행

- 상단의 주황색 **Start Attack** 버튼을 눌러 공격을 시작합니다.

![burp_intercept](imgs/attack%20img.png)

- 설정한 payload들이 비밀번호 자리에 순차적으로 대입되며 HTTP 요청이 반복 전송됩니다.


## 응답 분석

- 공격 결과 목록 중 **Length 컬럼 값이 다른 항목과 상이한 요청**이 발견됩니다.

![burp_intercept](imgs/attacking.png)

- 이는 기존 실패 응답과 다른 크기의 페이지를 서버가 반환했다는 의미로, 특정 payload가 **정상 인증에 성공한 응답**일 가능성이 높음을 나타냅니다.

- 확인 결과 해당 payload 값은 다음과 같습니다.
```text
password
```


## 로그인 검증

실제 로그인 화면에서

- Username: `admin`
- Password: `password`

를 입력해 로그인을 시도합니다.

![burp_intercept](imgs/login%20success.png)

결과로
```text
Welcome to the password protected area admin
```
메시지가 출력되며 관리자 계정 로그인에 성공한 것이 확인됩니다.
- 이를 통해 Burp Suite Intruder 기반 Brute Force attack이 정상적으로 성공했음을 확인합니다.

---

# 대응 방안


### 1. 로그인 시도 횟수 제한

- 일정 횟수 이상 로그인 실패 시 계정을 일시적으로 잠급니다.
- 예: 5회 실패 시 10분간 로그인 차단
- 이는 자동화된 무차별 대입 공격을 효과적으로 차단할 수 있습니다.

---

### 2. CAPTCHA 적용

- 로그인 요청 시 CAPTCHA를 적용하여
- 자동화 도구(Burp Intruder 등)의 반복 요청을 차단합니다.

---

### 3. 지연 시간(Delay) 적용

- 로그인 실패 시 일정 시간 응답을 지연시킵니다.
- 예: 실패할 때마다 1~2초 지연
- 공격자의 시도 속도를 크게 낮출 수 있습니다.

---

### 4. 2차 인증(2FA) 적용

- 아이디/비밀번호 외에 OTP, 인증 앱, SMS 인증 등을 추가합니다.
- 비밀번호가 노출되더라도 계정 탈취를 방지할 수 있습니다.

---

### 5. 강력한 비밀번호 정책 적용

- 최소 길이, 특수문자, 대소문자 혼합 등을 강제합니다.
- 사전 기반 공격(Dictionary Attack)을 어렵게 만듭니다.

---

### 6. 계정 잠금 및 알림 기능

- 비정상적인 로그인 시도 발생 시 관리자 또는 사용자에게 알림을 전송합니다.
- 의심 활동을 빠르게 인지하고 대응할 수 있습니다.

---

### 7. Rate Limiting 및 WAF 적용

- 특정 IP에서 일정 시간 내 과도한 요청이 발생할 경우 차단합니다.
- 웹 방화벽(WAF)을 통해 자동화 공격 패턴을 탐지 및 차단합니다.

---

## 정리

- Brute Force 공격은 기술적으로 복잡하지 않지만,  
  인증 설계가 미흡할 경우 매우 효과적인 공격 방식입니다.
- 로그인 시도 제한, 2차 인증, Rate Limiting 적용은  
  실무 환경에서 반드시 구현해야 하는 기본 보안 대책입니다.
- 인증 시스템은 단순 기능이 아니라  
  보안의 핵심 영역임을 인지해야 합니다.

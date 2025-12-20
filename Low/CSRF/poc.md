# CSRF (Cross-Site Request Forgery)

- **CSRF는 사용자가 로그인된 상태(인증 상태)를 악용하여, 사용자의 의도와 무관한 요청을 서버에 강제로 수행하게 만드는 취약점입니다.**

---

## 정상 동작 확인

- 다음은 `new password`와 `confirm new password`를 입력하여 비밀번호를 변경하는 페이지입니다.

![1](/Low/CSRF/imgs/1.png)

- 변경할 비밀번호로 `test`를 입력한 뒤 Burp Suite로 요청을 가로채(intercept) 확인했습니다.

![3](/Low/CSRF/imgs/3.png)

- 다음과 같은 GET 요청이 서버로 전송되는 것을 확인할 수 있습니다.

GET `/DVWA/vulnerabilities/csrf/?password_new=test&password_conf=test&Change=Change` HTTP/1.1

- 해당 요청은 **admin 계정의 비밀번호를 test로 변경하는 요청**입니다.

---

## GET 요청이란?

- **GET 요청은 URL에 파라미터를 포함하여 서버에 데이터를 전달하는 방식입니다.**
- 요청 내용이 URL에 그대로 노출되며, 링크 클릭만으로도 동일한 요청이 재전송될 수 있습니다.
- 비밀번호 변경과 같은 상태 변경 작업에 GET 요청을 사용하는 것은 매우 위험합니다.

---

## 비밀번호 변경 성공 확인

- 요청이 정상적으로 처리되면 비밀번호 변경이 완료됩니다.

![2](/Low/CSRF/imgs/2.png)

- 아래 URL에 직접 접속해도 동일하게 비밀번호가 변경되는 것을 확인할 수 있습니다.

`192.168.64.14/DVWA/vulnerabilities/csrf/?password_new=test&password_conf=test&Change=Change`

---

## 취약점 악용 방식

- 공격자는 위 URL을 피해자에게 전달하기만 해도 공격이 성립합니다.
- 피해자는 자신의 의사와 무관하게 비밀번호가 변경됩니다.
- 해당 계정이 관리자 계정일 경우 심각한 보안 사고로 이어질 수 있습니다.

---

## 공격 시나리오

- 공격자는 정상 사이트와 유사한 도메인을 사용하거나
- 하이퍼링크를 이용해 실제 URL을 숨긴 채 클릭을 유도할 수 있습니다.

---

## 이용한 공격 재현
### 필자는 하이퍼링크를 이용해 공격을 재현합니다
- 공격자는 실제 CSRF URL을 다음과 같이 하이퍼링크로 감출 수 있습니다.

<a href="192.168.64.14/DVWA/vulnerabilities/csrf/?password_new=test&password_conf=test&Change=Change">Check</a>

- 사용자는 실제 요청 내용을 확인하지 못한 채 Check라는 문자열만 보고 클릭하게 됩니다.

![4](/Low/CSRF/imgs/4.png)

- 필자의 개인 이메일로 전송해 하이퍼링크를 클릭해보았습니다.

![5](/Low/CSRF/imgs/5.png)

- 링크를 클릭하자마자 비밀번호가 변경되는 것을 확인할 수 있습니다.

![6](/Low/CSRF/imgs/6.png)

---

## 취약점 발생 원인

- 상태 변경 요청에 GET 메서드 사용
- CSRF 토큰 미적용
- 요청 출처(Origin / Referer) 검증 부재
- 중요 기능에 대한 추가 인증 미구현

---

## 이 취약점을 악용할 경우 가능한 공격

- 관리자 계정 탈취
- 계정 잠금 및 서비스 마비
- 권한 상승
- 추가 공격을 위한 초기 침투

---

## CSRF 예방법

- CSRF 취약점의 핵심은 **요청이 사용자의 의도에서 발생했는지 검증하지 않는 것**입니다.
- - CSRF 토큰 사용
  - POST 요청 사용
  - Referer / Origin 검증

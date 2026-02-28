# File Inclusion

- **File Inclusion은 사용자 입력값을 통해 서버가 의도하지 않은 파일을 포함하도록 만들어 내부 파일 노출이나 코드 실행으로 이어질 수 있는 웹 취약점입니다.**

---

## 정상 동작 확인

- 다음은 DVWA의 File Inclusion 실습 화면입니다.
- `file1.php`, `file2.php`, `file3.php` 총 3개의 파일이 존재하는 것을 확인할 수 있습니다.

![1](/Low/File%20Inclusion/imgs/1.png)

- 먼저 `file1.php`를 클릭해보겠습니다.

![2](/Low/File%20Inclusion/imgs/2.png)

- `file1.php`에 포함된 내용이 정상적으로 출력되는 것을 확인할 수 있습니다.

- 이어서 `file2.php`를 클릭해 파일 내용을 확인합니다.

![3](/Low/File%20Inclusion/imgs/3.png)

---

## URL 파라미터 분석

- URL을 자세히 보면 다음과 같은 형태를 확인할 수 있습니다.

```text
http://192.168.64.14/DVWA/vulnerabilities/fi/?page=file2.php
```
- 여기서 `page=file2.php`는 서버 측 코드에서 page 파라미터 값을 파일 경로로 그대로 사용해 `include()`를 수행하고 있음을 의미합니다.

---

## 사용자 입력 조작 확인

- 그렇다면 사용자가 URL을 직접 수정해 다른 파일을 불러올 수 있는지 확인해보겠습니다.
- URL의 `page` 파라미터를 `file3.php`로 변경합니다.

![4](/Low/File%20Inclusion/imgs/4.png)

- 예상대로 `file3.php`의 내용이 실행된 것을 확인할 수 있습니다.

![5](/Low/File%20Inclusion/imgs/5.png)

---

## 시스템 파일 접근 시도

- 다음으로, 서버에 존재하는 시스템 파일에 접근이 가능한지 확인합니다.
- 리눅스 시스템에 존재하는 모든 사용자 계정의 기본 정보는 `/etc/passwd` 파일에 저장되어 있습니다.
- 최상위 루트(`/`)로 이동하기 위해 `../`를 6번 이상 사용합니다.

- 필자는 다음과 같은 페이로드를 작성하였습니다.
```text
http://192.168.64.14/DVWA/vulnerabilities/fi/?page=../../../../../../etc/passwd
```
- 해당 URL로 접속한 결과, 시스템에 존재하는 사용자 계정 정보가 노출된 것을 확인할 수 있습니다.

![6](/Low/File%20Inclusion/imgs/6.png)

---

## Path Traversal 공격

- 위와 같은 공격 기법을 **Path Traversal 공격**이라고 합니다.
- **Path Traversal 공격은 `../`와 같은 경로 조작을 이용해 애플리케이션이 허용하지 않은 상위 디렉터리의 파일에 접근하도록 만드는 공격 기법입니다.**

---

## LFI (Local File Inclusion)

- 위 공격은 **LFI(Local File Inclusion)**에 해당합니다.
- LFI는 **서버 로컬에 존재하는 파일을 포함시켜 정보 노출로 이어지는 취약점**입니다.

---

## RFI (Remote File Inclusion)

- File Inclusion에는 또 다른 형태로 **RFI(Remote File Inclusion)**가 존재합니다.
- RFI는 **외부 URL의 파일을 서버가 포함하도록 유도하는 취약점**입니다.

- 다음은 RFI 기법을 사용한 공격 예시입니다.
```text
http://192.168.64.14/DVWA/vulnerabilities/fi/?page=https://naver.com
```

![7](/Low/File%20Inclusion/imgs/7.png)

- 그 결과, 외부 사이트의 내용이 서버를 통해 포함되어 출력되는 것을 확인할 수 있습니다.

![8](/Low/File%20Inclusion/imgs/8.png)

---

## 취약점 발생 원인

- 사용자 입력값에 대한 검증 부재
- 파일 경로에 대한 화이트리스트 미적용
- `include()` / `require()` 함수에 사용자 입력 직접 사용
- PHP 설정 상 원격 파일 포함 허용

---

## 이 취약점을 악용할 경우 가능한 공격

- 시스템 내부 파일 정보 노출
- 사용자 계정 정보 수집
- 소스 코드 노출
- 추가 취약점 탐색
- RCE(Remote Code Execution)로의 확장 가능성

---

# 대응방안

- File Inclusion의 핵심 원인은 **사용자 입력이 그대로 include() 경로로 사용되는 구조**입니다.

---

### 1. 화이트리스트 방식 적용 (가장 중요)

- 허용된 파일 목록만 배열로 정의
- 사용자 입력값이 목록에 존재할 경우에만 include 수행
- 직접 경로 입력 방식 금지

---

### 2. 절대 경로 기반 include 사용

- 상대 경로(`../`) 사용 금지
- 서버 내부에서 고정된 절대 경로로 파일 지정
- 문자열 결합 방식으로 경로 생성 금지

---

### 3. 경로 검증 로직 적용

- `realpath()`로 실제 경로 확인
- 기준 디렉토리 내부에 존재하는 파일인지 검증
- 디렉토리 탈출(`../`) 차단

---

### 4. PHP 설정 강화

- `allow_url_include = Off`
- `allow_url_fopen = Off` (필요 시)
- RFI 원천 차단

---

### 5. 최소 권한 원칙 적용

- 웹 서버 실행 계정 권한 최소화
- 중요 시스템 파일 접근 권한 제거
- 설정 파일 웹 루트 외부에 배치

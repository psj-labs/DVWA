# XSS (DOM Based)

- **DOM Based XSS는 서버가 아닌 브라우저의 JavaScript 로직에서 사용자 입력값이 그대로 DOM에 반영되어 스크립트가 실행되는 취약점입니다.**

---

## 정상 동작 확인

- 다음은 DVWA의 DOM Based XSS 실습 화면입니다.

![01](/Low/XSS%20(DOM)/imgs/01.png)

- 언어를 선택하면 URL에 `default` 파라미터가 추가됩니다.

![02](/Low/XSS%20(DOM)/imgs/02.png)

- 예:  
```
?default=English
```

- French로 변경하면 URL도 함께 변경됩니다.

![03](/Low/XSS%20(DOM)/imgs/03.png)

- 이를 통해 `GET` 방식으로 파라미터가 전달되고 있으며,
- 해당 값이 JavaScript에 의해 DOM에 반영되고 있음을 추측할 수 있습니다.

---

## 취약점 확인

- `default` 파라미터에 다음 페이로드를 주입합니다.

```
"><script>alert(1)</script>
```

![04](/Low/XSS%20(DOM)/imgs/04.png)

- 실행 결과, 브라우저에서 `alert(1)`이 실행됩니다.

![05](/Low/XSS%20(DOM)/imgs/05.png)

- 이는 사용자 입력값이 DOM에 그대로 삽입되어 스크립트가 실행된다는 의미입니다.

---

## 세션 탈취 가능성 확인

- 다음 페이로드를 입력합니다.

```
"><script>alert(document.cookie)</script>
```

![06](/Low/XSS%20(DOM)/imgs/06.png)

- 실행 결과, 현재 세션 쿠키 값이 출력됩니다.

![07](/Low/XSS%20(DOM)/imgs/07.png)

- 이를 통해 공격자는 세션 값을 탈취하여
- 세션 하이재킹 공격으로 이어질 수 있습니다.

---

## 취약점 발생 원인

- 사용자 입력값을 DOM에 직접 삽입
- innerHTML 사용
- 입력값에 대한 필터링 부재
- 출력 시 이스케이프 처리 미적용

---

## 대응방안

### 1. 입력값을 HTML로 직접 삽입하지 않기 (중요)

- `innerHTML` 사용 금지
- `textContent` 또는 `innerText` 사용

#### 취약한 예시
```
element.innerHTML = user_input;
```

#### 안전한 예시
```
element.textContent = user_input;
```

---

### 2. 출력 시 이스케이프 처리

- `<`, `>`, `"`, `'` 등 특수문자를 HTML 엔티티로 변환
- 서버 및 클라이언트 양쪽 모두 적용

---

### 3. CSP(Content Security Policy) 적용

- 인라인 스크립트 실행 차단
- 외부 스크립트 출처 제한

---

### 4. HttpOnly 쿠키 설정

- document.cookie 접근 차단
- 세션 탈취 방지

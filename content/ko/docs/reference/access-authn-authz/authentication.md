---
# reviewers:
# - erictune
# - lavalamp
# - deads2k
# - liggitt
title: 인증
content_type: concept
weight: 10
---

<!-- overview -->
이 페이지는에서는 인증 개요를 설명한다.


<!-- body -->
## 쿠버네티스의 사용자

모든 쿠버네티스 클러스터는 쿠버네티스가 관리하는 서비스 계정과 일반 사용자
두 가지 범주의 사용자가 있다.

클러스터-독립적인 서비스는 다음과 같은 방식으로 일반 사용자를 관리한다.

- Private key를 배포하는 관리자
- Keystone이나 Google 계정과 같은 사용자 저장소
- 사용자 이름과 비밀번호 목록이 있는 파일

위의 항목에 따르면, _쿠버네티스는 일반 사용자 계정을 나타내는 오브젝트가 없다._
일반 사용자 계정은 API 호출을 통해 클러스터에 추가될 수 없다.

API 호출을 통해 일반 사용자를 추가할 수는 없지만, 클러스터의 인증서 기관(CA)에 의해 
서명된 유효한 인증서를 제시하는 모든 사용자는 인증된 것으로 간주된다.
이 구성에서 쿠버네티스는 인증서의 'subject'의 공통 이름 필드(예: "/CN=bob")에서 
사용자 이름을 결정한다.
그런 다음, 역할 기반 접근 제어(RBAC) 하위 시스템은 사용자가 
특정 작업을 수행할 수 있는지 여부를 결정한다. 
자세한 내용은 [인증서 요청](/docs/reference/access-authn-authz/certificate-signing-requests/#normal-user)을 참조

반면, 서비스 계정은 쿠버네티스 API에 의해 관리되는 사용자이다. 
서비스 계정은 특정 네임스페이스에 바인딩되며, 
API 서버에 의해 자동으로 생성되거나 API 호출을 통해 수동으로 생성된다. 
서비스 계정은 `Secrets`로 저장된 일련의 자격 증명과 연결되어 있으며, 
이는 파드에 마운트되어 클러스터 내부 프로세스가 쿠버네티스 API와 통신할 수 있게 한다.

API 요청은 일반 사용자나 서비스 계정에 바인딩되거나 [익명 요청](#anonymous-requests)으로 처리된다. 
이는 워크스테이션에서 'kubectl'을 입력하는 사용자부터 노드의 
'kubelet' 및 control-plane 멤버까지, 
클러스터 내부 또는 외부의 모든 프로세스가 API 서버에 요청을 보낼 때 
인증해야 하거나 익명 사용자로 처리되어야 함을 의미한다.

## 인증 전략(Authentication strategies)

쿠버네티스는 API 요청을 인증하기 위해 클라이언트 인증서, bearer token 
또는 인증 프록시를 사용하여 인증 전략을 구현한다. 
API 서버로 HTTP 요청이 전송될 때, 
플러그인은 다음과 같은 속성을 요청과 연관시키려고 한다:

* 사용자 이름(Username): 엔드 유저를 식별하는 문자열이다. 일반적으로 `kube-admin` 또는 `jane@example.com`과 같은 값을 가질 수 있다.
* 사용자 식별자(UID): 사용자를 식별하는 문자열로, 사용자 이름보다 일관되고 고유하게 설정된다.
* 그룹(Group): 사용자가 소속된 명명된 논리적인 사용자 집합을 나타내는 문자열의 집합이다. 일반적으로 `system:masters` 또는 `devops-team`과 같은 값을 가질 수 있다.
* 추가 필드(Extra fields): 인가자(authorizer)가 유용하게 활용할 수 있는 추가 정보를 문자열에서 문자열 리스트로 매핑한 map이다.

이러한 값들은 인증 시스템에 대해 알 수 없으며 
[인가자](/docs/reference/access-authn-authz/authorization/)가 해석할 때에만 의미가 있다.

여러 인증 방법을 동시에 활성화할 수도 있다. 일반적으로 다음과 같은 방법을 사용해야 한다.

- 서비스 계정을 위한 서비스 계정 토큰
- 사용자 인증을 위한 적어도 하나의 다른 방법

여러 개의 인증 모듈이 활성화된 경우, 
첫 번째로 요청을 성공적으로 인증하는 모듈이 평가를 중단시킨다. 
API 서버는 인증자가 실행되는 순서를 보장하지 않는다.

`system:authenticated` 그룹은 모든 인증된 사용자의 그룹 목록에 포함된다.

다른 인증 프로토콜(LDAP, SAML, Kerberos, 대체 x509 스키마 등)과의 통합은 
[인증 프록시](#authenticating-proxy) 또는
[인증 웹훅](#webhook-token-authentication)을 사용하여 수행할 수 있다.

### X509 클라이언트 인증서(X509 Client Certs)

클라이언트 인증서를 사용한 인증은 API 서버에 `--client-ca-file=SOMEFILE`옵션을 전달하여 
활성화된다. 참조된 파일은 API 서버에 제시된 클라이언트 인증서를 검증하는 데 사용할 
하나 이상의 인증 기관을 포함해야 한다. 클라이언트 인증서가 제시되고 확인된 경우, 
주체의 공통 이름이 요청의 사용자 이름으로 사용된다. 쿠버네티스 1.4부터는 클라이언트 인증서의 
조직 필드를 사용하여 사용자의 그룹 소속을 나타낼 수도 있다. 사용자에 대해 여러 그룹 소속을 
포함하려면 인증서에 여러 조직 필드를 포함하면 된다.

예를 들어, `openssl` 명령 줄 도구를 사용하여 인증서 서명 요청을 생성하는 방법은 다음과 같다.

``` bash
openssl req -new -key jbeda.pem -out jbeda-csr.pem -subj "/CN=jbeda/O=app1/O=app2"
```

다음은 "jbeda"라는 사용자 이름을 가진 CSR을 생성하며, "app1"과 "app2"라는 두 개의 그룹에 속하는 예시이다.

클라이언트 인증서를 생성하는 방법에 대해서는 .[인증서 관리](/docs/tasks/administer-cluster/certificates/)를 참조.

### 정적 토큰 파일

API 서버는 커맨드 라인에서 `--token-auth-file=SOMEFILE` 옵션을 주면 파일에서 
bearer token을 읽는다. 현재 토큰은 무기한으로 유지되며, 토큰 목록을 변경하려면 
API 서버를 재시작해야 한다.

토큰 파일은 최소 3개의 열(토큰, 사용자 이름, 사용자 UID)로 구성된 CSV 파일이다. 
선택적으로 그룹 이름을 추가할 수도 있다.

{{< note >}}
여러 개의 그룹이 있는 경우, 해당 열은 이중 인용부호로 감싸야 한다. 예:

```conf
token,user,uid,"group1,group2,group3"
```
{{< /note >}}

#### HTTP request에 Bearer Token 넣기

HTTP 클라이언트에서 bearer token 인증을 사용할 때, API 서버는 Authorization 헤더에 
`Bearer <토큰>` 값이 들어있을 것을 기대한다. bearer token은 HTTP의 인코딩 및 
인용 기능을 사용하여 HTTP 헤더 값에 넣을 수 있는 문자열 시퀀스여야 한다. 
예를 들어, bearer token이 `31ada4fd-adec-460c-809a-9e56ceb75269`라면 
아래와 같이 HTTP 헤더에 표시된다.

```http
Authorization: Bearer 31ada4fd-adec-460c-809a-9e56ceb75269
```

### 부트스트랩 토큰

{{< feature-state for_k8s_version="v1.18" state="stable" >}}

새로운 클러스터에 대한 간소화된 부트스트래핑을 위해, 쿠버네티스는 *Bootstrap Token*이라고 
불리는 동적으로 관리된 bearer token을 포함한다. 이러한 토큰은 `kube-system` 네임스페이스의 
Secrets로 저장되어 동적으로 관리하고 생성할 수 있다. 컨트롤러 매니저에는 만료되는 부트스트랩 
토큰을 삭제하는 TokenCleaner 컨트롤러가 포함되어 있다.

토큰은 [a-z0-9]{6}.[a-z0-9]{16} 형식을 가지고 있다. 첫 번째 구성 요소는 토큰 ID이고, 
두 번째 구성 요소는 토큰 Secret이다. 토큰은 다음과 같이 HTTP 헤더에 지정한다:

```http
Authorization: Bearer 781292.db7bc3a58fc5f07e
```

API 서버에서는 `--enable-bootstrap-token-auth` 플래그를 사용하여 
부트스트랩 토큰 인증을 활성화해야 한다. 컨트롤러 매니저에서는 `--controllers` 
플래그를 사용하여 TokenCleaner 컨트롤러를 활성화해야 한다. 
예를 들어 `--controllers=*,tokencleaner`와 같이 설정한다. 
클러스터 부트스트래핑에 kubeadm을 사용하는 경우, 이 작업은 `kubeadm`이 대신 수행해준다.

인증자는 `system:bootstrap:<Token ID>`로 인증된다. 
이는 `system:bootstrappers` 그룹에 포함된다. 이러한 네이밍과 그룹은 의도적으로 
부트스트래핑 이후에 이러한 토큰을 사용하지 않도록 제한되어 있다.
사용자 이름과 그룹은 (그리고 `kubeadm`에서 사용되는 대로) 클러스터 부트스트래핑을 
지원하기 위해 적절한 인가 정책을 작성하는 데 사용될 수 있다.

부트스트랩 토큰 인증자와 컨트롤러에 대한 자세한 문서 및 `kubeadm`을 사용하여 이러한 
토큰을 관리하는 방법은 [부트스트랩 토큰](/docs/reference/access-authn-authz/bootstrap-tokens/)을 참조.

### 서비스 계정 토큰

서비스 계정은 요청을 검증하기 위해 서명된 bearer token을 사용하는 자동으로 활성화된 
인증자이다. 이 플러그인은 두 개의 선택적인 플래그를 사용한다:

*`--service-account-key-file`: 서비스 계정 토큰을 검증하는 데 사용되는 PEM 형식의 
x509 RSA 또는 ECDSA 개인 또는 공개 키가 포함된 파일이다. 지정된 파일에는 여러 개의 
키가 포함될 수 있으며, 다른 파일과 함께 여러 번의 플래그로 지정할 수 있다. 
지정되지 않은 경우, --tls-private-key-file이 사용된다.
*`--service-account-lookup`: 활성화된 경우, API에서 삭제된 토큰은 폐기된다.

서비스 계정은 일반적으로 API 서버에 의해 자동으로 생성되며 `ServiceAccount`[Admission Controller](/docs/reference/access-authn-authz/admission-controllers/)를 통해 
클러스터에서 실행 중인 파드와 연결된다. bearer token은 알려진 위치의 파드에 마운트되어 
클러스터 내부 프로세스가 API 서버와 통신할 수 있게 한다. `PodSpec`의 
`serviceAccountName` 필드를 사용하여 계정을 명시적으로 파드와 연관시킬 수도 있다.

{{< note >}}
`serviceAccountName`은 자동으로 처리되기에 보통 생략된다.
{{< /note >}}

```yaml
apiVersion: apps/v1 # 이 API버전은 쿠버네티스 1.9부터 지원된다.
kind: Deployment
metadata:
  name: nginx-deployment
  namespace: default
spec:
  replicas: 3
  template:
    metadata:
    # ...
    spec:
      serviceAccountName: bob-the-bot
      containers:
      - name: nginx
        image: nginx:1.14.2
```

클러스터 외부에서도 서비스 계정 bearer token은 완벽하게 유효하며, 쿠버네티스 API와 
통신하려는 장기 실행 작업에 대한 신원을 생성하는 데 사용할 수 있다. 수동으로 
서비스 계정을 생성하려면 `kubectl create serviceaccount (이름)` 명령을 사용하자. 
이렇게 하면 현재 네임스페이스에 서비스 계정이 생성된다.

```bash
kubectl create serviceaccount jenkins
```

```none
serviceaccount/jenkins created
```

associated token 만들기:

```bash
kubectl create token jenkins
```

```none
eyJhbGciOiJSUzI1NiIsImtp...
```

생성된 토큰은 서명된 JSON Web Token (JWT)이다.

서명된 JWT는 주어진 서비스 계정으로 인증하는 데 사용할 수 있는 bearer token으로 
사용될 수 있다. 토큰을 요청에 포함하는 방법에 대해서는 [위의 내용](#putting-a-bearer-token-in-a-request)을 참조. 
일반적으로 이러한 토큰은 파드에 마운트되어 클러스터 내에서 API 서버에 접근하는 데 
사용되지만, 클러스터 외부에서도 사용할 수 있다.

서비스 계정은 `system:serviceaccount:(네임스페이스):(서비스 계정)`과 같은 사용자 
이름으로 인증되며, 
`system:serviceaccounts` 및 `system:serviceaccounts:(네임스페이스)` 그룹에 할당된다.

{{< warning >}}
서비스 계정 토큰은 Secret API 오브젝트에 저장될 수도 있기 때문에 Secrets에 대한 
쓰기 액세스 권한을 가진 사용자는 토큰을 요청할 수 있으며, 해당 Secrets에 대한 
읽기 액세스 권한을 가진 사용자는 서비스 계정으로 인증할 수 있다. 서비스 계정에 대한 
권한 및 Secrets에 대한 읽기 또는 쓰기 기능을 부여할 때 주의가 필요하다. 
사용자에게 부여하는 권한을 신중하게 관리해야 한다.
{{< /warning >}}

### OpenID Connect 토큰

[OpenID Connect](https://openid.net/connect/)는 OAuth2를 지원하는 일부 OAuth2 공급자, 
특히 Azure Active Directory, Salesforce 및 Google에서 지원하는 OAuth2의 변형이다. 
이 프로토콜은 OAuth2의 주요 확장 기능으로 액세스 토큰과 함께 반환되는 [ID 토큰](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)
이라는 추가 필드를 가지고 있다. 이 토큰은 서버에 의해 서명된 사용자의 이메일과 같은 
잘 알려진 필드가 포함된 JSON Web Token (JWT)이다.

사용자를 식별하기 위해 인증자는 OAuth2 [토큰 응답](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)에서 
`id_token`(access_token 아님)을 bearer token으로 사용한다. 토큰이 요청에 포함되는 
방법에 대해서는 [위의 내용](#putting-a-bearer-token-in-a-request)을 참조.

{{< mermaid >}}
sequenceDiagram
    participant user as User
    participant idp as Identity Provider
    participant kube as Kubectl
    participant api as API Server

    user ->> idp: 1. IdP에 로그인
    activate idp
    idp -->> user: 2. access_token, id_token,<br>refresh_token 제공
    deactivate idp
    activate user
    user ->> kube: 3. id_token이 존재하면<br> --token 옵션으로 Kubectl 호출<br>또는 .kube/config애 토큰 추가
    deactivate user
    activate kube
    kube ->> api: 4. Authorization: Bearer...
    deactivate kube
    activate api
    api ->> api: 5. JWT 가 유효한가?
    api ->> api: 6. JWT가 만료되었는가? (iat+exp)
    api ->> api: 7. 사용자는 인증되었는가?
    api -->> kube: 8. Authorized: 액션 수행<br>및 결과 반환
    deactivate api
    activate kube
    kube --x user: 9. 결과 반환
    deactivate kube
{{< /mermaid >}}

1.  아이덴티티 제공자에 로그인한다.
2.  아이덴티티 제공자는 `access_token`, `id_token`, `refresh_token`을 제공한다.
3.  `kubectl`을 사용할 때 `id_token`을 `--token` 플래그와 함께 사용하거나 직접 `kubeconfig`에 추가한다.
4.  `kubectl`은 `id_token`을 Authorization 헤더에 담아 API 서버로 전송한다.
5.  API 서버는 구성에서 지정된 인증서와 비교하여 JWT 서명이 유효한지 확인한다.
6.  `id_token`이 만료되지 않았는지 확인한다.
7.  사용자에게 권한이 있는지 확인한다.
8.  권한이 부여되면 API 서버가 `kubectl`에 응답을 반환한다.
9.  `kubectl`은 사용자에게 피드백을 제공한다.


쿠버네티스는 신원 제공자로 "통신"할 필요가 없기 때문에 신원을 확인하는 데 필요한 
모든 데이터가 `id_token`에 포함되어 있다. 모든 요청이 상태를 유지하지 않는(stateless) 
모델에서는 인증에 대한 확장 가능한 솔루션을 제공한다. 그러나 몇 가지 어려움이 있을 수 있다.

1. 쿠버네티스에는 인증 프로세스를 시작할 수 있는 "웹 인터페이스"가 없다. 자격 증명을 수집할 수 있는 브라우저나 인터페이스가 없으므로 먼저 신원 제공자에 대해 인증해야 한다
2. `id_token`은 취소할 수 없으며, 인증서와 유사하게 동작한다. 따라서 토큰은 수명이 짧아야 한다(몇 분 정도). 이로 인해 몇 분마다 새 토큰을 가져와야 하는 번거로움이 있을 수 있다.
3. 쿠버네티스 대시보드에 인증하려면 `kubectl proxy` 명령을 사용하거나 `id_token`을 삽입하는 리버스 프록시를 사용해야 한다.

#### API 서버 설정

플러그인을 활성화 하기위해 API서버에 다음과 같은 플래그를 설정한다:

| Parameter | Description | Example | Required |
| --------- | ----------- | ------- | ------- |
| `--oidc-issuer-url` | API 서버가 공개 서명 키를 검색할 수 있게 하는 제공자의 URL이다. `https://` 스킴을 사용하는 URL만 허용된다. 일반적으로 경로가 없는 제공자의 검색 URL이며, 예를 들어 "https://accounts.google.com" 또는 "https://login.salesforce.com"과 같은 형식이다. 이 URL은 .well-known/openid-configuration 아래의 수준을 가리켜야 한다. | 만약 검색 URL이 `https://accounts.google.com/.well-known/openid-configuration`라면, 값은 `https://accounts.google.com`이어야 한다. | Yes |
| `--oidc-client-id` | 모든 토큰이 발급되어야 하는 클라이언트 ID이다. | kubernetes | Yes |
| `--oidc-username-claim` | 사용자 이름으로 사용할 JWT 클레임이다. 기본값은 `sub`이며, 이는 최종 사용자의 고유 식별자로 사용된다. 관리자는 제공자에 따라 `email` 또는 `name`과 같은 다른 클레임을 선택할 수 있다. 그러나, 제공자에 따라서 외의 클레임은 다른 플러그인과의 이름 충돌을 방지하기 위해 발급자 URL과 접두사가 붙게 된다. | sub | No |
| `--oidc-username-prefix` | 기존 이름(예: `system:` 사용자)과 충돌을 방지하기 위해 사용자 이름 클레임 앞에 추가되는 접두사이다. 예를 들어, 값으로 `oidc:`를 지정하면 `oidc:jane.doe`와 같은 사용자 이름이 생성된다. 이 플래그가 제공되지 않고 `--oidc-username-claim`이 `email`이 아닌 다른 값을 가지는 경우, 접두사는 `(발급자 URL)#`의 형식으로 기본값으로 설정된다. 여기서 `(발급자 URL)`은 `--oidc-issuer-url`의 값이다. `-` 값을 사용하여 모든 접두사를 비활성화할 수도 있다. | `oidc:` | No |
| `--oidc-groups-claim` | 사용자 그룹으로 사용하기 위한 JWT claim 이다. 해당 클레임이 존재하는 경우, 그룹은 문자열 배열이어야 한다. | groups | No |
| `--oidc-groups-prefix` | 기존 이름(예: `system:` 그룹)과 충돌을 방지하기 위해 그룹 클레임 앞에 추가되는 접두사이다. 예를 들어, 값으로 `oidc:`를 지정하면 `oidc:engineering` 및 `oidc:infra`와 같은 그룹 이름이 생성된다. | `oidc:` | No |
| `--oidc-required-claim` |ID 토큰에서 필요한 클레임을 설명하는 key=value 쌍이다. 설정된 경우, 해당 클레임이 일치하는 값을 가진 ID 토큰에 있는지 확인한다. 여러 개의 클레임을 지정하려면 이 플래그를 반복하여 사용하세요. | `claim=value` | No |
| `--oidc-ca-file` | 신원 제공자의 웹 인증서를 서명한 CA의 인증서 경로이다. 기본값은 호스트의 루트 CA이다. `/etc/kubernetes/ssl/kc-ca.pem`와 같은 경로를 사용할 수 있다. | No |
| `--oidc-signing-algs` | 허용된 서명 알고리즘 이다. 기본값은 "RS256"이다.. | `RS512` | No |

중요한 점은 API 서버가 OAuth2 클라이언트가 아니라는 것이다. 
대신 단일 발급자(trust a single issuer)를 신뢰하도록 구성할 수 있다. 이는 
구글과 같은 공공 제공자(public providers)를 신뢰하지 않고도 제3자에게 발급된 
자격 증명을 사용할 수 있도록 한다. 여러 OAuth 클라이언트를 사용하고자 하는 
관리자는 다른 클라이언트가 다른 클라이언트를 대신하여 토큰을 발급하는 메커니즘으로 
`azp` (authorized party) 클레임을 지원하는 제공자를 탐색해야 한다.

쿠버네티스는 OpenID Connect Identity Provider를 제공하지 않는다.
이미 제공된 퍼블릭 OpenID Connect Identity Provider를 사용할 수 있다
(예: Google, or [others](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk/openid-connect-providers)). 또는 여러분이 직접만든 제공자를 사용할 수도 있다. 
예를 들어 [dex](https://dexidp.io/),
[Keycloak](https://github.com/keycloak/keycloak),
CloudFoundry [UAA](https://github.com/cloudfoundry/uaa), 또는
Tremolo Security의 [OpenUnison](https://openunison.github.io/)등이 있다.

쿠버네티스와 함께 작동하려면 신원 제공자는 다음 요구 사항을 충족해야 한다.

1.  [OpenID connect discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)지원; 모든 신원자가 지원하진 않는다.
2.  TLS를 사용하여 사용되지 않는 암호화 알고리즘을 피함
3.  CA에 의해 서명된 인증서 보유 (상업용 CA가 아니거나 자체 서명된 것이라도 가능)

강조할 점은 위에서 언급한 요구 사항 #3에 대한 내용인데, 신원 제공자를 직접 배포하는 경우 
(Google이나 Microsoft와 같은 클라우드 제공자가 아닌 경우) 신원 제공자의 웹 서버 인증서는 
`CA` 플래그가 `TRUE`로 설정된 인증서에 의해 서명되어야 한다. 이 인증서는 자체 서명된 
것일지라도 해당된다. 이는 GoLang의 TLS 클라이언트 구현이 인증서 유효성 검사에 대해 
매우 엄격하게 준수해야 하는 표준 때문이다. CA가 없는 경우 Dex 팀에서 제공하는 [이 스크립트](https://github.com/dexidp/dex/blob/master/examples/k8s/gencert.sh)를 
사용하여 간단한 CA 및 서명된 인증서와 키 쌍을 생성할 수 있다. 또는 [이 유사한 스크립트](https://raw.githubusercontent.com/TremoloSecurity/openunison-qs-kubernetes/master/src/main/bash/makessl.sh)를 
사용할 수도 있다. 이 스크립트는 수명이 더 길고 키 사이즈가 큰 SHA256 인증서를 생성한다. 

구체적인 시스템을 위한 설정 지침서:

- [UAA](https://docs.cloudfoundry.org/concepts/architecture/uaa.html)
- [Dex](https://dexidp.io/docs/kubernetes/)
- [OpenUnison](https://www.tremolosecurity.com/orchestra-k8s/)

#### kubectl 사용

##### 옵션 1 - OIDC 인증기

첫 번째 옵션은 kubectl의 `oidc` 인증기를 사용하는 것이다. 이 옵션은 `id_token`을 
모든 요청의 bearer token으로 설정하고 토큰이 만료되면 토큰을 자동으로 갱신한다. 
공급자에 로그인한 후 kubectl을 사용하여 `id_token`, `refresh_token`, `client_id` 
및 `client_secret`을 추가하여 플러그인을 구성한다.

리프레시 토큰 응답의 일부로 `id_token`을 반환하지 않는 공급자는 이 플러그인을 지원하지 
않으며, 아래의 "option 2"를 사용해야 한다.

```bash
kubectl config set-credentials USER_NAME \
   --auth-provider=oidc \
   --auth-provider-arg=idp-issuer-url=( issuer url ) \
   --auth-provider-arg=client-id=( your client id ) \
   --auth-provider-arg=client-secret=( your client secret ) \
   --auth-provider-arg=refresh-token=( your refresh token ) \
   --auth-provider-arg=idp-certificate-authority=( path to your ca certificate ) \
   --auth-provider-arg=id-token=( your id_token )
```

예를 들어, 신원 제공자에 인증 후 아래의 커맨드를 실행:

```bash
kubectl config set-credentials mmosley  \
        --auth-provider=oidc  \
        --auth-provider-arg=idp-issuer-url=https://oidcidp.tremolo.lan:8443/auth/idp/OidcIdP  \
        --auth-provider-arg=client-id=kubernetes  \
        --auth-provider-arg=client-secret=1db158f6-177d-4d9c-8a8b-d36869918ec5  \
        --auth-provider-arg=refresh-token=q1bKLFOyUiosTfawzA93TzZIDzH2TNa2SMm0zEiPKTUwME6BkEo6Sql5yUWVBSWpKUGphaWpxSVAfekBOZbBhaEW+VlFUeVRGcluyVF5JT4+haZmPsluFoFu5XkpXk5BXqHega4GAXlF+ma+vmYpFcHe5eZR+slBFpZKtQA= \
        --auth-provider-arg=idp-certificate-authority=/root/ca.pem \
        --auth-provider-arg=id-token=eyJraWQiOiJDTj1vaWRjaWRwLnRyZW1vbG8ubGFuLCBPVT1EZW1vLCBPPVRybWVvbG8gU2VjdXJpdHksIEw9QXJsaW5ndG9uLCBTVD1WaXJnaW5pYSwgQz1VUy1DTj1rdWJlLWNhLTEyMDIxNDc5MjEwMzYwNzMyMTUyIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL29pZGNpZHAudHJlbW9sby5sYW46ODQ0My9hdXRoL2lkcC9PaWRjSWRQIiwiYXVkIjoia3ViZXJuZXRlcyIsImV4cCI6MTQ4MzU0OTUxMSwianRpIjoiMm96US15TXdFcHV4WDlHZUhQdy1hZyIsImlhdCI6MTQ4MzU0OTQ1MSwibmJmIjoxNDgzNTQ5MzMxLCJzdWIiOiI0YWViMzdiYS1iNjQ1LTQ4ZmQtYWIzMC0xYTAxZWU0MWUyMTgifQ.w6p4J_6qQ1HzTG9nrEOrubxIMb9K5hzcMPxc9IxPx2K4xO9l-oFiUw93daH3m5pluP6K7eOE6txBuRVfEcpJSwlelsOsW8gb8VJcnzMS9EnZpeA0tW_p-mnkFc3VcfyXuhe5R3G7aa5d8uHv70yJ9Y3-UhjiN9EhpMdfPAoEB9fYKKkJRzF7utTTIPGrSaSU6d2pcpfYKaxIwePzEkT4DfcQthoZdy9ucNvvLoi1DIC-UocFD8HLs8LYKEqSxQvOcvnThbObJ9af71EwmuE21fO5KzMW20KtAeget1gnldOosPtz1G5EwvaQ401-RPQzPGMVBld0_zMCAwZttJ4knw
```

아래와 같은 설정을 생성할 것 이다:

```yaml
users:
- name: mmosley
  user:
    auth-provider:
      config:
        client-id: kubernetes
        client-secret: 1db158f6-177d-4d9c-8a8b-d36869918ec5
        id-token: eyJraWQiOiJDTj1vaWRjaWRwLnRyZW1vbG8ubGFuLCBPVT1EZW1vLCBPPVRybWVvbG8gU2VjdXJpdHksIEw9QXJsaW5ndG9uLCBTVD1WaXJnaW5pYSwgQz1VUy1DTj1rdWJlLWNhLTEyMDIxNDc5MjEwMzYwNzMyMTUyIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL29pZGNpZHAudHJlbW9sby5sYW46ODQ0My9hdXRoL2lkcC9PaWRjSWRQIiwiYXVkIjoia3ViZXJuZXRlcyIsImV4cCI6MTQ4MzU0OTUxMSwianRpIjoiMm96US15TXdFcHV4WDlHZUhQdy1hZyIsImlhdCI6MTQ4MzU0OTQ1MSwibmJmIjoxNDgzNTQ5MzMxLCJzdWIiOiI0YWViMzdiYS1iNjQ1LTQ4ZmQtYWIzMC0xYTAxZWU0MWUyMTgifQ.w6p4J_6qQ1HzTG9nrEOrubxIMb9K5hzcMPxc9IxPx2K4xO9l-oFiUw93daH3m5pluP6K7eOE6txBuRVfEcpJSwlelsOsW8gb8VJcnzMS9EnZpeA0tW_p-mnkFc3VcfyXuhe5R3G7aa5d8uHv70yJ9Y3-UhjiN9EhpMdfPAoEB9fYKKkJRzF7utTTIPGrSaSU6d2pcpfYKaxIwePzEkT4DfcQthoZdy9ucNvvLoi1DIC-UocFD8HLs8LYKEqSxQvOcvnThbObJ9af71EwmuE21fO5KzMW20KtAeget1gnldOosPtz1G5EwvaQ401-RPQzPGMVBld0_zMCAwZttJ4knw
        idp-certificate-authority: /root/ca.pem
        idp-issuer-url: https://oidcidp.tremolo.lan:8443/auth/idp/OidcIdP
        refresh-token: q1bKLFOyUiosTfawzA93TzZIDzH2TNa2SMm0zEiPKTUwME6BkEo6Sql5yUWVBSWpKUGphaWpxSVAfekBOZbBhaEW+VlFUeVRGcluyVF5JT4+haZmPsluFoFu5XkpXk5BXq
      name: oidc
```

`id_token`이 만료 되면, `kubectl`는 `refresh_token` 과 `client_secret`을 이용해 
`id_token'을 갱신하려고 시도 할 것이며 `refresh_token` 과 `id_token`을 위한 
새로운 값을 `.kube/config`에 저장할 것이다.

##### 옵션 2 - `--token` 옵션 사용

`kubectl` 명령어는 `--token` 옵션을 사용하여 토큰을 전달할 수 있다. 
이 옵션에 `id_token`을 복사하여 붙혀넣는다:

```bash
kubectl --token=eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL21sYi50cmVtb2xvLmxhbjo4MDQzL2F1dGgvaWRwL29pZGMiLCJhdWQiOiJrdWJlcm5ldGVzIiwiZXhwIjoxNDc0NTk2NjY5LCJqdGkiOiI2RDUzNXoxUEpFNjJOR3QxaWVyYm9RIiwiaWF0IjoxNDc0NTk2MzY5LCJuYmYiOjE0NzQ1OTYyNDksInN1YiI6Im13aW5kdSIsInVzZXJfcm9sZSI6WyJ1c2VycyIsIm5ldy1uYW1lc3BhY2Utdmlld2VyIl0sImVtYWlsIjoibXdpbmR1QG5vbW9yZWplZGkuY29tIn0.f2As579n9VNoaKzoF-dOQGmXkFKf1FMyNV0-va_B63jn-_n9LGSCca_6IVMP8pO-Zb4KvRqGyTP0r3HkHxYy5c81AnIh8ijarruczl-TK_yF5akjSTHFZD-0gRzlevBDiH8Q79NAr-ky0P4iIXS8lY9Vnjch5MF74Zx0c3alKJHJUnnpjIACByfF2SCaYzbWFMUNat-K1PaUk5-ujMBG7yYnr95xD-63n8CO8teGUAAEMx6zRjzfhnhbzX-ajwZLGwGUBT4WqjMs70-6a7_8gZmLZb2az1cZynkFRj2BaCkVT3A2RrjeEwZEtGXlMqKJ1_I2ulrOVsYx01_yD35-rw get nodes
```


### 웹훅 토큰 인증

웹훅 인증은 bearer token을 검증하기 위한 hook이다.

* `--authentication-token-webhook-config-file' 원격 웹훅 서비스에 액세스하는 방법을 설명하는 구성 파일이다.
* `--authentication-token-webhook-cache-ttl` 인증 결정을 캐시하는 시간을 설정한다. 기본값은 2분이다.
* `--authentication-token-webhook-version` 웹훅과 정보를 주고받기 위해 `authentication.k8s.io/v1beta1` 또는 `authentication.k8s.io/v1` `TokenReview` 오브젝트를 사용할지를 결정한다. 기본값은 v1beta1이다.

구성 파일은 [kubeconfig](/docs/concepts/configuration/organize-cluster-access-kubeconfig/)파일 형식을 사용한다. 파일 내에서 
`clusters`는 원격 서비스를 나타내며, `users`는 API 서버 웹훅을 나타낸다. 
예시는 다음과 같다.

```yaml
# 쿠버네티스 API 버전
apiVersion: v1
# API 오브젝트 종류
kind: Config
# 원격 서비스를 참조해 클러스터 설정.
clusters:
  - name: name-of-remote-authn-service
    cluster:
      certificate-authority: /path/to/ca.pem         # 원격지를 검증하기 위한 CA
      server: https://authn.example.com/authenticate # 원격지를 조회하기위한 URL. 프로덕션환경 에서 'https' 사용을 권장.

# API서버의 웹훅 설정을 참조해 사용자 설정
users:
  - name: name-of-api-server
    user:
      client-certificate: /path/to/cert.pem # cert for the webhook plugin to use
      client-key: /path/to/key.pem          # key matching the cert

# kubeconfig 파일은 context를 필요로 함. API server를 위해 제공.
current-context: webhook
contexts:
- context:
    cluster: name-of-remote-authn-service
    user: name-of-api-server
  name: webhook
```

클라이언트가 [위에서](#putting-a-bearer-token-in-a-request), 언급한 대로 bearer token을 
사용하여 API 서버에 인증을 시도할 때, 인증 웹훅은 해당 토큰을 포함한 직렬화된 JSON
`TokenReview` 오브젝트를 원격 서비스에게 POST한다.

웹훅 API 오브젝트는 다른 쿠버네티스 API 오브젝트와 동일한 버전 호환성 규칙에 따른다. 
구현자는 요청의 `apiVersion` 필드를 확인하여 올바른 역직렬화가 이루어졌는지 확인해야 하며, 
**반드시** 요청과 동일한 버전의 `TokenReview` 오브젝트로 응답해야 한다.

{{< tabs name="TokenReview_request" >}}
{{% tab name="authentication.k8s.io/v1" %}}
{{< note >}}
쿠버네티스 API 서버는 하위 호환성을 위해 기본적으로 `authentication.k8s.io/v1beta1` 토큰 리뷰를 전송한다. 
`authentication.k8s.io/v1` 토큰 리뷰 수신을 통해 옵트인하려면 API 서버를 `--authentication-token-webhook-version=v1` 옵션으로 시작해야 한다.
{{< /note >}}

```yaml
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "spec": {
    # API 서버로 보내진 불분명한 bearer token
    "token": "014fbff9a07c...",
   
    # 토큰이 제시된 서버를 위한 대상 식별자의 목록.
    # 대상 식별자를 고려한(Audience-aware) 토큰 인증기 (예를 들어, OIDC 토큰 인증기)는 
    # 목록에 포함된 대상 식별자(audiences) 중 적어도 하나를 대상으로 토큰이 의도되었는지 확인해야 한다.
    # 그리고 응답 상태에서 이 목록과 토큰의 유효 대상 식별자들의 교집합을 반환해야 한다.
    # 이는 이미 제공되었던 서버의 토큰이 유효한지 확실시한다. 
    # 만약 대상 식별자(audienes)가 제공되지 않는다면, 토큰은 쿠버네티스 API 서버를 인증하기위해 검증되어야 한다. 
    "audiences": ["https://myserver.example.com", "https://myserver.internal.example.com"]
  }
}
```
{{% /tab %}}
{{% tab name="authentication.k8s.io/v1beta1" %}}
```yaml
{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "TokenReview",
  "spec": {
    # API 서버로 보내진 불분명한 bearer token
    "token": "014fbff9a07c...",
   
    # 토큰이 제시된 서버를 위한 대상 식별자의 목록.
    # 대상 식별자를 고려한(Audience-aware) 토큰 인증기 (예를 들어, OIDC 토큰 인증기)는 
    # 목록에 포함된 대상 식별자(audiences) 중 적어도 하나를 대상으로 토큰이 의도되었는지 확인해야 한다.
    # 그리고 응답 상태에서 이 목록과 토큰의 유효 대상 식별자들의 교집합을 반환해야 한다.
    # 이는 이미 제공되었던 서버의 토큰이 유효한지 확실시한다. 
    # 만약 대상 식별자(audienes)가 제공되지 않는다면, 토큰은 쿠버네티스 API 서버를 인증하기위해 검증되어야 한다. 
    "audiences": ["https://myserver.example.com", "https://myserver.internal.example.com"]
  }
}
```
{{% /tab %}}
{{< /tabs >}}

원격 서비스는 요청의 `status` 필드를 채워서 로그인 성공 여부를 나타내야 한다. 
응답 본문의 `spec` 필드는 무시되고 생략될 수 있다. 원격 서비스는 받은 
`TokenReview API` 버전과 동일한 버전의 응답을 반환해야 한다. 
bearer token의 유효성을 성공적으로 확인한 경우 다음과 같은 응답이 반환된다.

{{< tabs name="TokenReview_response_success" >}}
{{% tab name="authentication.k8s.io/v1" %}}
```yaml
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "status": {
    "authenticated": true,
    "user": {
      # 필수
      "username": "janedoe@example.com",
      # 선택사항
      "uid": "42",
      # 선택사항인 그룹 멤버십
      "groups": ["developers", "qa"],
      # 선택사항인 인증기에 의해 제공된 추가 정보
      # 로그, 또는 API 오브젝트로 기록되고, 어드미션 웹훅을 사용가능하게 만들 때
      # 계정 데이터를 포함하지 않아야한다.
      "extra": {
        "extrafield1": [
          "extravalue1",
          "extravalue2"
        ]
      }
    },
    # 선택 사항인 대상 식별자 기반(Audience-aware) 토큰 인증기는 반환할 수 있으며,
    # `spec.audiences` 목록에 제공된 토큰이 유효했던 대상 식별자들을 포함한다.
    # 이 부분이 생략되면, 해당 토큰은 쿠버네티스 API 서버에 인증하기 유효하다고 간주된다.
    "audiences": ["https://myserver.example.com"]
  }
}
```
{{% /tab %}}
{{% tab name="authentication.k8s.io/v1beta1" %}}
```yaml
{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "TokenReview",
  "status": {
    "authenticated": true,
    "user": {
      # 필수
      "username": "janedoe@example.com",
      # 선택사항
      "uid": "42",
      # 선택사항인 그룹 멤버십
      "groups": ["developers", "qa"],
      # 선택사항인 인증기에 의해 제공된 추가 정보
      # 로그, 또는 API 오브젝트로 기록되고, 어드미션 웹훅을 사용가능하게 만들 때
      # 계정 데이터를 포함하지 않아야한다.
      "extra": {
        "extrafield1": [
          "extravalue1",
          "extravalue2"
        ]
      }
    },
    # 선택 사항인 대상 식별자 기반(Audience-aware) 토큰 인증기는 반환할 수 있으며,
    # `spec.audiences` 목록에 제공된 토큰이 유효했던 대상 식별자들을 포함한다.
    # 이 부분이 생략되면, 해당 토큰은 쿠버네티스 API 서버에 인증하기 유효하다고 간주된다.
    "audiences": ["https://myserver.example.com"]
  }
}
```
{{% /tab %}}
{{< /tabs >}}

성공적이지 못한 요청에 대해 다음과 같이 반환된다.

{{< tabs name="TokenReview_response_error" >}}
{{% tab name="authentication.k8s.io/v1" %}}
```yaml
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "status": {
    "authenticated": false,
    # 인증 실패 이유에 대한 세부 정보를 선택적으로 포함할 수 있다.
    # 만약 오류가 제공되지 않은 경우, API는 일반적인 "Unauthorized" 메시지를 반환.
    # 오류 필드는 authenticated=true인 경우 무시된다.
    "error": "Credentials are expired"
  }
}
```
{{% /tab %}}
{{% tab name="authentication.k8s.io/v1beta1" %}}
```yaml
{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "TokenReview",
  "status": {
    "authenticated": false,
    # 인증 실패 이유에 대한 세부 정보를 선택적으로 포함할 수 있다.
    # 만약 오류가 제공되지 않은 경우, API는 일반적인 "Unauthorized" 메시지를 반환.
    # 오류 필드는 authenticated=true인 경우 무시된다.
    "error": "Credentials are expired"
  }
}
```
{{% /tab %}}
{{< /tabs >}}

### 인증 프록시

API 서버는 `X-Remote-User`와 같은 요청 헤더 값에서 사용자를 식별할 수 있도록 
구성할 수 있다. 이는 요청 헤더 값을 설정하는 인증 프록시와 함께 사용하기 위해 설계되었다.

* `--requestheader-username-headers` 필수이며 대소문자를 구분하지 않는다. 사용자 신원을 확인하기 위해 확인할 헤더 이름들을 순서대로 지정한다. 값이 포함된 첫 번째 헤더가 사용자 이름으로 사용된다.
* `--requestheader-group-headers` 1.6+. 선택적이며 대소문자를 구분하지 않는다. "X-Remote-Group" 헤더를 사용하는 것이 권장된다. 사용자의 그룹을 확인하기 위해 확인할 헤더 이름들을 순서대로 지정한다. 지정된 모든 헤더들에 있는 모든 값들이 그룹 이름으로 사용된다.
* `--requestheader-extra-headers-prefix` 1.6+. 선택적이며 대소문자를 구분하지 않는다. "X-Remote-Extra-"가 권장된다. 사용자에 대한 추가 정보를 확인하기 위해 사용되는 헤더 접두사들을 지정한다 (일반적으로 구성된 권한 부여 플러그인에 의해 사용됨). 지정된 접두사로 시작하는 모든 헤더는 해당 접두사가 제거된다. 그 이후의 헤더 이름은 소문자로 변환되며, [퍼센트 디코딩](https://tools.ietf.org/html/rfc3986#section-2.1)이 수행되어 추가 키(extra key)가 된다. 헤더 값은 추가 값(extra value)이 된다.

{{< note >}}
이전 버전인 1.11.3 이전 (그리고 1.10.7, 1.9.11)에서는 추가 키(extra key)에는 [HTTP 헤더 레이블로 허용되는 문자](https://tools.ietf.org/html/rfc7230#section-3.2.6)만 포함될 수 있었다.
{{< /note >}}

예를 들어 다음 설정과 함께:

```
--requestheader-username-headers=X-Remote-User
--requestheader-group-headers=X-Remote-Group
--requestheader-extra-headers-prefix=X-Remote-Extra-
```

다음 요청을 보내면:

```http
GET / HTTP/1.1
X-Remote-User: fido
X-Remote-Group: dogs
X-Remote-Group: dachshunds
X-Remote-Extra-Acme.com%2Fproject: some-project
X-Remote-Extra-Scopes: openid
X-Remote-Extra-Scopes: profile
```

사용자 정보 결과는 이렇게 될 것이다:

```yaml
name: fido
groups:
- dogs
- dachshunds
extra:
  acme.com/project:
  - some-project
  scopes:
  - openid
  - profile
```



헤더 변조를 방지하기 위해 인증 프록시는 요청 헤더를 확인하기 전에 API 서버에 대해 유효한 
클라이언트 인증서를 제시하고 지정된 CA(인증 기관)를 통해 인증되어야 한다. 다른 컨텍스트에서 
사용된 CA를 재사용하지 말아야 한다. 
경고! : CA의 사용을 보호하는 리스크와 메커니즘을 이해하지 못한채로 
다른 context에서 사용되는 CA를 **재사용 하지말자**

* `--requestheader-client-ca-file`필수 항목이다. PEM 인코딩된 인증서 번들(Certificate Bundle)을 지정한다. 요청 헤더를 확인하기 전에 유효한 클라이언트 인증서가 지정된 파일의 CA 인증 기관에 대해 인증되어야 한다. 이를 통해 인증 프록시는 클라이언트의 신원을 검증하고, 변조되지 않은 요청인지 확인할 수 있다.
* `--requestheader-allowed-names` 선택적 옵션이다. Common Name 값(CN)들의 리스트이다. 이 옵션을 설정하면 유효한 클라이언트 인증서가 해당 리스트에 지정된 CN 중 하나를 가져야만 요청 헤더를 확인하기 전에 사용자 이름을 확인할 수 있다. 만약 이 옵션이 비어있다면, 모든 CN이 허용된다. 이 옵션을 사용하여 특정 CN만 허용하도록 설정할 수 있다.


## 익명 요청

활성화된 경우, 다른 구성된 인증 방법에서 거부되지 않은 요청은 익명 요청으로 취급되며, 
사용자 이름은 `system:anonymous`로, 그룹은 `system:unauthenticated`로 설정된다.

예를 들어, 토큰 인증이 구성된 서버에서 익명 액세스가 활성화된 경우, 유효하지 않은 bearer 
token을 제공하는 요청은 `401 Unauthorized` 오류를 받게 된다. bearer token을 제공하지 않는 
요청은 익명 요청으로 처리된다.

1.5.1-1.5.x 버전에서는 익명 액세스가 기본적으로 비활성화되어 있으며, 
API 서버에 `--anonymous-auth=true` 옵션을 전달하여 활성화할 수 있다.

1.6 이상 버전에서는 인가 모드가 AlwaysAllow가 아닌 경우 익명 액세스가 기본적으로 활성화되며, 
API 서버에 `--anonymous-auth=false` 옵션을 전달하여 비활성화할 수 있다. 1.6 버전부터 
ABAC와 RBAC 인가자(authorizer)는 `system:anonymous` 사용자 또는 `system:unauthenticated` 
그룹의 명시적인 권한 부여를 요구하므로, `*` 사용자 또는 `*` 그룹에 액세스 권한을 부여하는 
기존 정책 규칙은 익명 사용자를 포함하지 않는다.

## 사용자 위임(User impersonation)

사용자는 위임(impersonation) 헤더를 통해 다른 사용자로 작동할 수 있다. 이를 통해 요청이 
인증하는 사용자 정보를 수동으로 덮어쓸 수 있다. 예를 들어, 관리자는 이 기능을 사용하여 
임시로 다른 사용자를 모방하고 요청이 거부되는지 확인하여 권한 정책을 디버깅할 수 있다.

위임 요청은 먼저 요청하는 사용자로 인증을 수행한 후, 이후에 모방된 사용자 정보로 전환된다.

* 사용자는 자신의 자격 증명과 위임 헤더를 함께 API 호출을 수행한다.
* API 서버는 사용자를 인증한다.
* API 서버는 인증된 사용자가 위임 권한을 가지고 있는지 확인한다.
* 요청된 사용자 정보는 위임된 값으로 대체된다.
* 요청은 평가되고, 권한 부여는 위임된 사용자 정보를 기반으로 실행된다.

다음 HTTP 헤더를 사용하여 위임 요청을 수행할 수 있다:

* `Impersonate-User`: 동작할 사용자 이름이다.
* `Impersonate-Group`: 동작할 그룹 이름이다. 여러 번 제공하여 여러 그룹을 설정할 수 있다. 선택 사항이다. "Impersonate-User"가 필요한다.
* `Impersonate-Extra-( extra name )`: 용자와 추가 필드를 연결하는 데 사용되는 동적 헤더이다. 선택 사항이다. "Impersonate-User"가 필요한다. 일관되게 유지하려면 `(extra name)`은 소문자여야하며, [HTTP 헤더 라벨로 허용되는 문자](https://tools.ietf.org/html/rfc7230#section-3.2.6)가 아닌 모든 문자는 utf8 및 [퍼센트 인코딩](https://tools.ietf.org/html/rfc3986#section-2.1)되어야한다.
* `Impersonate-Uid`: 사용자를 위임하는 데 사용되는 고유 식별자이다. 선택 사항이다. "Impersonate-User"가 필요한다. 쿠버네티스에서는 이 문자열에 대해 어떤 형식 요구 사항도 부과하지 않는다.

{{< note >}}
1.11.3 이전(그리고 1.10.7, 1.9.11)까지는, `( extra name )`은 [HTTP헤더 라벨로 허용되는 문자](https://tools.ietf.org/html/rfc7230#section-3.2.6)만을 포함해야 했다.
{{< /note >}}

{{< note >}}
`Impersonate-Uid`은 1.22.0 이상 버전에서만 사용가능 한다.
{{< /note >}}

사용자 그룹을 포함하여 사용자를 위장할 때 사용되는 위임 헤더의 예시이다::
```http
Impersonate-User: jane.doe@example.com
Impersonate-Group: developers
Impersonate-Group: admins
```

사용자 UID와 추가 필드를 포함하여 사용자를 위장할 때 사용되는 위임 헤더의 예시이다:
```http
Impersonate-User: jane.doe@example.com
Impersonate-Extra-dn: cn=jane,ou=engineers,dc=example,dc=com
Impersonate-Extra-acme.com%2Fproject: some-project
Impersonate-Extra-scopes: view
Impersonate-Extra-scopes: development
Impersonate-Uid: 06f6ce97-e2c5-4ab8-7ba5-7654dd08d52b
```


`kubectl`을 사용하여 `Impersonate-User` 헤더를 구성하려면 `--as` 플래그를 설정하고, 
`Impersonate-Group` 헤더를 구성하려면 `--as-group` 플래그를 설정한다.

```bash
kubectl drain mynode
```

```none
Error from server (Forbidden): User "clark" cannot get nodes at the cluster scope. (get nodes mynode)
```

`--as` 와 `--as-group` 플래그를 지정한다:

```bash
kubectl drain mynode --as=superman --as-group=system:masters
```

```none
node/mynode cordoned
node/mynode drained
```

{{< note >}}
`kubectl`는 extra fields 또는 UIDs를 위장할 수 없다.
{{< /note >}}

사용자, 그룹, 사용자 식별자(UID) 또는 추가 필드를 위장하기 위해서는 위임하는 사용자가 위임 
대상 속성 종류("user", "group", "uid" 등)에 대해 "impersonate" 동작을 수행할 수 있는 권한을 
가져야 한다. RBAC 권한 부여 플러그인이 활성화된 클러스터의 경우, 다음 ClusterRole은 사용자와 
그룹 위임 헤더를 설정하기 위해 필요한 규칙을 포함한다:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: impersonator
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]
```


사용자를 위임하기 위해, 추가 필드 및 위임된 UID는 모두 "authentication.k8s.io" `apiGroup` 아래에 있다.
추가 필드는 "userextras" 리소스의 하위 리소스로 평가된다. 사용자가 "scopes" 추가 필드와 
UID에 대해 위임 헤더를 사용할 수 있도록 하려면 사용자에게 다음과 같은 역할(Role)을 
부여해야 한다:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: scopes-and-uid-impersonator
rules:
# "Impersonate-Extra-scopes" 헤더와 "Impersonate-Uid" 헤더를 설정할 수 있다.
- apiGroups: ["authentication.k8s.io"]
  resources: ["userextras/scopes", "uids"]
  verbs: ["impersonate"]
```

위임 헤더의 값은 `resourceNames` 집합을 제한함으로써 추가로 제한될 수 있다.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: limited-impersonator
rules:
# "jane.doe@example.com" 사용자 위임 가능
- apiGroups: [""]
  resources: ["users"]
  verbs: ["impersonate"]
  resourceNames: ["jane.doe@example.com"]

# "developers" and "admins" 그룹 위임 가능
- apiGroups: [""]
  resources: ["groups"]
  verbs: ["impersonate"]
  resourceNames: ["developers","admins"]

# "view" and "development"값을 포함하는 extras field "scopes" 위임 가능
- apiGroups: ["authentication.k8s.io"]
  resources: ["userextras/scopes"]
  verbs: ["impersonate"]
  resourceNames: ["view", "development"]

# uid "06f6ce97-e2c5-4ab8-7ba5-7654dd08d52b" 위임 가능
- apiGroups: ["authentication.k8s.io"]
  resources: ["uids"]
  verbs: ["impersonate"]
  resourceNames: ["06f6ce97-e2c5-4ab8-7ba5-7654dd08d52b"]
```

{{< note >}}
사용자 또는 그룹을 위장하면 해당 사용자나 그룹으로서 원하는 모든 작업을 수행할 수 있다. 이러한 이유로 인해 위임은 네임스페이스 범위로 제한되지 않는다.
쿠버네티스 RBAC를 사용하여 위임을 허용하려면 `Role`과 `RoleBinding`이 아닌 `ClusterRole`과 `ClusterRoleBinding`을 사용해야 한다.
{{< /note >}}

## go 클라이언트 계정 플러그인(client-go credential plugins)

{{< feature-state for_k8s_version="v1.22" state="stable" >}}

`k8s.io/client-go` 및 `kubectl`, `kubelet`과 같은 이를 사용하는 도구들은 외부 명령을 
실행하여 사용자 자격 증명을 받아올 수 있다.

이 기능은 `k8s.io/client-go`에서 원래 지원하지 않는 인증 프로토콜 (LDAP, Kerberos, 
OAuth2, SAML 등)과 클라이언트 사이드 통합을 위해 고안되었다. 이 플러그인은 프로토콜 
특정 로직을 구현하고, 불투명한(opaque) 자격 증명을 반환하여 사용한다. 대부분의 자격 
증명 플러그인은 클라이언트 플러그인에 의해 생성된 자격 증명 형식을 해석할 수 있도록 
서버 측 구성 요소를 필요로 한다. 이를 위해 [웹훅 토큰 인증기](#webhook-token-authentication)를 지원하는 서버 측 
구성 요소가 필요할 수 있다.


### 사용 예시(Example use case)

해당 가상의 사용 사례에서는 조직이 LDAP 자격 증명을 사용자별로 서명된 토큰으로 교환하는 
외부 서비스를 실행한다. 이 서비스는 또한 [웹훅 토큰 인증기](#webhook-token-authentication) 요청에 대해 토큰의 
유효성 검사 기능도 갖추고 있다. 사용자들은 자신의 작업 환경에 자격 증명 플러그인을 
설치해야 한다.

API에 대한 인증 절차는 다음과 같다:

* 사용자가 `kubectl` 명령을 실행한다.
* 자격 증명 플러그인은 사용자에게 LDAP 자격 증명을 요청하고, 자격 증명을 외부 서비스와 교환하여 토큰을 받아온다.
* 자격 증명 플러그인은 토큰을 client-go에 반환하며, client-go는 이 토큰을 API 서버에 대한 bearer token으로 사용한다.
* API 서버는 [웹훅 토큰 인증기](#webhook-token-authentication)를 사용하여 외부 서비스에게 `TokenReview`를 제출한다.
* 외부 서비스는 토큰의 서명을 확인하고 사용자의 사용자 이름과 그룹을 반환한다.

### 설정(Configuration)

계정 플러그인은 [kubectl config files](/docs/tasks/access-application-cluster/configure-access-multiple-clusters/)를 통해 사용자 필드의 부분으로 설정된다.

{{< tabs name="exec_plugin_kubeconfig_example_1" >}}
{{% tab name="client.authentication.k8s.io/v1" %}}
```yaml
apiVersion: v1
kind: Config
users:
- name: my-user
  user:
    exec:
      # 실행할 명령어, 필수
      command: "example-client-go-exec-plugin"

      # ExecCredentials 리소스를 디코딩할 때 사용할 API 버전이다. 필수 항목이다.
      #
      # 플러그인이 반환하는 API 버전은 여기에 나열된 버전과 일치해야 한다.
      #
      # 다중 버전을 지원하는 도구(client.authentication.k8s.io/v1beta1과 같은)와 통합하려면, 
      # 환경 변수를 설정하거나,
      # 플러그인이 기대하는 버전을 나타내는 인수를 도구에 전달하거나, 
      # KUBERNETES_EXEC_INFO 환경 변수 내의 ExecCredential 개체에서 
      # 버전을 읽어와야 한다. 이를 통해 플러그인이 지원하는 API 버전을 
      # 명확하게 지정할 수 있다.
      apiVersion: "client.authentication.k8s.io/v1beta1"

      # 플러그인을 실행할 때에 환경변수 설정. 선택사항.
      env:
      - name: "FOO"
        value: "bar"

      # 플러그인을 실행할때 넘기는 인자들, 선택사항.
      args:
      - "arg1"
      - "arg2"

      # 실행 파일이 존재하지 않는 경우 사용자에게 표시되는 텍스트이다. 선택 사항.
      installHint: |
        example-client-go-exec-plugin is required to authenticate
        to the current cluster.  It can be installed:

        On macOS: brew install example-client-go-exec-plugin

        On Ubuntu: apt-get install example-client-go-exec-plugin

        On Fedora: dnf install example-client-go-exec-plugin

        ...

      # KUBERNETES_EXEC_INFO 환경 변수의 일부로 exec 플러그인에 대해 매우 큰 CA 데이터를 
      # 포함시킬지 여부는 해당 플러그인과 클러스터의 특정 요구사항에 따른다.
      provideClusterInfo: true

      # exec 플러그인과 표준 입력 (stdin) I/O 스트림 간의 계약. 계약이 만족되지 않으면
      # 플러그인은 동작하지 않고 에러를 반환한다. 
      # 유효값은 "Never" (표준입력으로 절대 사용하지않음),
      # "IfAvailable" (사용가능할때만 표준입력으로 사용), "Always" (표준입력이 반드시 필요)
      # 가 있다. 필수
      interactiveMode: Never
clusters:
- name: my-cluster
  cluster:
    server: "https://172.17.4.100:6443"
    certificate-authority: "/etc/kubernetes/ca.pem"
    extensions:
    - name: client.authentication.k8s.io/exec # 클러스터당 실행 설정을 위해 예약된 익스텐션(extension) 이름
      extension:
        arbitrary: config
        this: can be provided via the KUBERNETES_EXEC_INFO environment variable upon setting provideClusterInfo
        you: ["can", "put", "anything", "here"]
contexts:
- name: my-cluster
  context:
    cluster: my-cluster
    user: my-user
current-context: my-cluster
```
{{% /tab %}}
{{% tab name="client.authentication.k8s.io/v1beta1" %}}
```yaml
apiVersion: v1
kind: Config
users:
- name: my-user
  user:
    exec:
      # 실행할 명령어, 필수
      command: "example-client-go-exec-plugin"

      # ExecCredentials 리소스를 디코딩할 때 사용할 API 버전이다. 필수 항목이다.
      #
      # 플러그인이 반환하는 API 버전은 여기에 나열된 버전과 일치해야 한다.
      #
      # 다중 버전을 지원하는 도구(client.authentication.k8s.io/v1과 같은)와 통합하려면, 
      # 환경 변수를 설정하거나,
      # 플러그인이 기대하는 버전을 나타내는 인수를 도구에 전달하거나, 
      # KUBERNETES_EXEC_INFO 환경 변수 내의 ExecCredential 개체에서 
      # 버전을 읽어와야 한다. 이를 통해 플러그인이 지원하는 API 버전을 
      # 명확하게 지정할 수 있다.
      apiVersion: "client.authentication.k8s.io/v1beta1"

      # 플러그인을 실행할 때에 환경변수 설정 선택사항.
      env:
      - name: "FOO"
        value: "bar"

      # 플러그인을 실행할때 넘기는 인자들, 선택사항.
      args:
      - "arg1"
      - "arg2"

      # 실행 파일이 존재하지 않는 경우 사용자에게 표시되는 텍스트이다. 선택 사항.
      installHint: |
        example-client-go-exec-plugin is required to authenticate
        to the current cluster.  It can be installed:

        On macOS: brew install example-client-go-exec-plugin

        On Ubuntu: apt-get install example-client-go-exec-plugin

        On Fedora: dnf install example-client-go-exec-plugin

        ...

      # KUBERNETES_EXEC_INFO 환경 변수의 일부로 exec 플러그인에 대해 매우 큰 CA 데이터를 포함시킬지 
      # 여부는 해당 플러그인과 클러스터의 특정 요구사항에 따른다.
      provideClusterInfo: true

      # exec 플러그인과 표준 입력 (stdin) I/O 스트림 간의 계약. 계약이 만족되지 않으면
      # 플러그인은 동작하지 않고 에러를 반환한다. 유효값은 "Never" (표준입력으로 절대 사용하지않음),
      # "IfAvailable" (사용가능할때만 표준입력으로 사용), "Always" (표준입력이 반드시 필요)
      # 가 있으며 선택할 수 있다. 기본값은 "IfAvailable"이다.
      interactiveMode: Never
clusters:
- name: my-cluster
  cluster:
    server: "https://172.17.4.100:6443"
    certificate-authority: "/etc/kubernetes/ca.pem"
    extensions:
    - name: client.authentication.k8s.io/exec # 클러스터당 실행 설정을 위해 예약된 익스텐션(extension) 이름 
      extension:
        arbitrary: config
        this: can be provided via the KUBERNETES_EXEC_INFO environment variable upon setting provideClusterInfo
        you: ["can", "put", "anything", "here"]
contexts:
- name: my-cluster
  context:
    cluster: my-cluster
    user: my-user
current-context: my-cluster
```
{{% /tab %}}
{{< /tabs >}}

쿠버네티스에서는 상대적인 명령 경로가 설정 파일의 디렉토리를 기준으로 해석된다. 만약 
`KUBECONFIG`가 `/home/jane/kubeconfig`로 설정되어 있고, 실행(exec) 명령이 
`./bin/example-client-go-exec-plugin`로 지정되었다면, 바이너리 
`/home/jane/bin/example-client-go-exec-plugin`가 실행된다.

```yaml
- name: my-user
  user:
    exec:
      # Path relative to the directory of the kubeconfig
      command: "./bin/example-client-go-exec-plugin"
      apiVersion: "client.authentication.k8s.io/v1"
      interactiveMode: Never
```

### 입출력 포맷(Input and output formats)

실행된 명령은 `stdout`에 `ExecCredential` 오브젝트를 출력한다. `k8s.io/client-go`는 이러한 
반환된 자격 증명을 `status`에서 사용하여 쿠버네티스 API에 대해 인증한다. 실행된 명령은 
`KUBERNETES_EXEC_INFO` 환경 변수를 통해 입력으로 `ExecCredential` 오브젝트를 전달받는다. 
이 입력에는 반환된 `ExecCredential` 오브젝트의 예상 API 버전 및 플러그인이 `stdin`을 사용하여 
사용자와 상호 작용할 수 있는지 여부와 같은 유용한 정보가 포함되어 있다.

인터랙티브 세션(예: 터미널)에서 실행되는 경우, 플러그인은 `stdin`을 직접 사용할 수 있다. 
플러그인은 `KUBERNETES_EXEC_INFO` 환경 변수에서 입력으로 받은 `ExecCredential` 오브젝트의 
`spec.interactive` 필드를 사용하여 `stdin`이 제공되었는지를 확인한다. 플러그인이 `stdin`을 
사용하는 요구 사항(예: `stdin`이 선택적인지, 엄격하게 필요한지, 또는 플러그인이 성공적으로 
실행되기 위해 전혀 사용되지 않는지)은 `kubeconfig` 파일의 `user.exec.interactiveMode` 
필드에서 선언된다. (유효한 값에 대한 테이블은 아래 참조) `user.exec.interactiveMode` 필드는 
`client.authentication.k8s.io/v1beta1`에서 선택 사항이며 
`client.authentication.k8s.io/v1`에서 필수이다.

{{< table caption="interactiveMode values" >}}
| `interactiveMode` Value | Meaning |
| ----------------------- | ------- |
| `Never` | 이 exec 플러그인은 절대로 표준 입력을 사용할 필요가 없으므로, 사용자 입력에 대한 표준 입력이 가능한지 여부와 관계없이 실행될 것이다. |
| `IfAvailable` | 이 exec 플러그인은 가능하다면 표준 입력을 사용하려고 하지만, 표준 입력이 없더라도 동작할 수 있다. 따라서 사용자 입력을 위해 표준 입력이 있는지 여부와 관계없이 exec 플러그인이 실행될 것이다. 만약 표준 입력이 사용 가능하다면, 해당 exec 플러그인에게 제공될 것이다. |
| `Always` | 이 exec 플러그인은 실행에 표준 입력을 필수로 요구하며, 따라서 사용자 입력을 위해 표준 입력이 있는 경우에만 실행될 것이다. 만약 사용자 입력을 위한 표준 입력이 제공되지 않으면 exec 플러그인은 실행되지 않으며, exec 플러그인 runner에 의해 오류가 반환될 것이다. |
{{< /table >}}

bearer token 인증을 사용하기 위해선, 플러그인은
[`ExecCredential`](/docs/reference/config-api/client-authentication.v1beta1/#client-authentication-k8s-io-v1beta1-ExecCredential)상태의 토큰을 반환한다.

{{< tabs name="exec_plugin_ExecCredential_example_1" >}}
{{% tab name="client.authentication.k8s.io/v1" %}}
```json
{
  "apiVersion": "client.authentication.k8s.io/v1",
  "kind": "ExecCredential",
  "status": {
    "token": "my-bearer-token"
  }
}
```
{{% /tab %}}
{{% tab name="client.authentication.k8s.io/v1beta1" %}}
```json
{
  "apiVersion": "client.authentication.k8s.io/v1beta1",
  "kind": "ExecCredential",
  "status": {
    "token": "my-bearer-token"
  }
}
```
{{% /tab %}}
{{< /tabs >}}

또 다른 방법으로, TLS 클라이언트 인증을 위해 PEM 인코딩된 클라이언트 인증서와 개인 키를 반환할 
수 있다. 플러그인이 이후의 호출에서 다른 인증서와 개인 키를 반환하는 경우, `k8s.io/client-go`
는 서버와의 새로운 TLS 핸드쉐이크를 위해 기존 연결을 닫을 것이다.

만약 `clientKeyData`와 `clientCertificateData`가 지정된 경우, 두 값 모두 존재해야 한다.

`clientCertificateData`에는 서버로 보낼 추가 중간 인증서를 포함시킬 수 있다.

{{< tabs name="exec_plugin_ExecCredential_example_2" >}}
{{% tab name="client.authentication.k8s.io/v1" %}}
```json
{
  "apiVersion": "client.authentication.k8s.io/v1",
  "kind": "ExecCredential",
  "status": {
    "clientCertificateData": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "clientKeyData": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
}
```
{{% /tab %}}
{{% tab name="client.authentication.k8s.io/v1beta1" %}}
```json
{
  "apiVersion": "client.authentication.k8s.io/v1beta1",
  "kind": "ExecCredential",
  "status": {
    "clientCertificateData": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "clientKeyData": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
}
```
{{% /tab %}}
{{< /tabs >}}

선택적으로, 응답에 자격 증명의 만료 시간을 [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339) 형식의 타임스탬프로 포함할 수 있다.

만료 시간의 포함 또는 미포함에는 다음과 같은 영향이 있다:

- 만료 시간이 포함된 경우, bearer token과 TLS 자격 증명은 만료 시간에 도달할 때까지 캐시되거나 서버가 401 HTTP 상태 코드로 응답하거나 프로세스가 종료될 때까지 캐시된다.
- 만료 시간이 누락된 경우, bearer token과 TLS 자격 증명은 서버가 401 HTTP 상태 코드로 응답하거나 프로세스가 종료될 때까지 캐시된다.

{{< tabs name="exec_plugin_ExecCredential_example_3" >}}
{{% tab name="client.authentication.k8s.io/v1" %}}
```json
{
  "apiVersion": "client.authentication.k8s.io/v1",
  "kind": "ExecCredential",
  "status": {
    "token": "my-bearer-token",
    "expirationTimestamp": "2018-03-05T17:30:20-08:00"
  }
}
```
{{% /tab %}}
{{% tab name="client.authentication.k8s.io/v1beta1" %}}
```json
{
  "apiVersion": "client.authentication.k8s.io/v1beta1",
  "kind": "ExecCredential",
  "status": {
    "token": "my-bearer-token",
    "expirationTimestamp": "2018-03-05T17:30:20-08:00"
  }
}
```
{{% /tab %}}
{{< /tabs >}}

Exec 플러그인이 클러스터별 정보를 얻을 수 있도록 하려면 [kubeconfig](/docs/concepts/configuration/organize-cluster-access-kubeconfig/) 파일의 
`user.exec` 필드에 `provideClusterInfo`를 `true`로 설정하자. 이렇게 하면 플러그인은 
`KUBERNETES_EXEC_INFO` 환경 변수를 통해 해당 클러스터에 대한 정보를 제공받을 수 있다. 
이 환경 변수에서 얻은 정보를 사용하여 클러스터별 자격 증명 로직을 수행할 수 있다.
아래는 클러스터 정보 예제를 설명하는 `ExecCredential` 매니페스트이다.

{{< tabs name="exec_plugin_ExecCredential_example_4" >}}
{{% tab name="client.authentication.k8s.io/v1" %}}
```json
{
  "apiVersion": "client.authentication.k8s.io/v1",
  "kind": "ExecCredential",
  "spec": {
    "cluster": {
      "server": "https://172.17.4.100:6443",
      "certificate-authority-data": "LS0t...",
      "config": {
        "arbitrary": "config",
        "this": "can be provided via the KUBERNETES_EXEC_INFO environment variable upon setting provideClusterInfo",
        "you": ["can", "put", "anything", "here"]
      }
    },
    "interactive": true
  }
}
```
{{% /tab %}}
{{% tab name="client.authentication.k8s.io/v1beta1" %}}
```json
{
  "apiVersion": "client.authentication.k8s.io/v1beta1",
  "kind": "ExecCredential",
  "spec": {
    "cluster": {
      "server": "https://172.17.4.100:6443",
      "certificate-authority-data": "LS0t...",
      "config": {
        "arbitrary": "config",
        "this": "can be provided via the KUBERNETES_EXEC_INFO environment variable upon setting provideClusterInfo",
        "you": ["can", "put", "anything", "here"]
      }
    },
    "interactive": true
  }
}
```
{{% /tab %}}
{{< /tabs >}}

## 클라이언트의 인증 정보에 대한 API 액세스 {#self-subject-review}

{{< feature-state for_k8s_version="v1.27" state="beta" >}}

만약 클러스터가 API를 활성화한 경우, `SelfSubjectReview` API를 사용하여 쿠버네티스 클러스터가 
클라이언트로서 당신을 식별하기 위해 어떻게 인증 정보를 매핑하는지 확인할 수 있다. 이는 사용자
(일반적으로 실제 사람을 나타냄) 또는 ServiceAccount로서 인증하는 경우 모두 작동한다.

`SelfSubjectReview` 오브젝트에는 구성 가능한 필드가 없다. 요청을 받으면 쿠버네티스 API 서버는 
사용자 속성으로 상태를 채우고 사용자에게 반환한다.

요청 예제 (요청 본문은 `SelfSubjectReview`가 될 것이다):
```
POST /apis/authentication.k8s.io/v1beta1/selfsubjectreviews
```
```json
{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "SelfSubjectReview"
}
```
Response example:

```json
{
  "apiVersion": "authentication.k8s.io/v1beta1",
  "kind": "SelfSubjectReview",
  "status": {
    "userInfo": {
      "name": "jane.doe",
      "uid": "b6c7cfd4-f166-11ec-8ea0-0242ac120002",
      "groups": [
        "viewers",
        "editors",
        "system:authenticated"
      ],
      "extra": {
        "provider_id": ["token.company.example"]
      }
    }
  }
}
```

편의를 위해, `kubectl auth whoami` 명령이 제공된다. 이 명령을 실행하면 다음과 유사한 출력이 
생성된다 (단, 사용자 속성은 다를 수 있다):

* Simple output example
    ```
    ATTRIBUTE         VALUE
    Username          jane.doe
    Groups            [system:authenticated]
    ```

* Complex example including extra attributes
    ```
    ATTRIBUTE         VALUE
    Username          jane.doe
    UID               b79dbf30-0c6a-11ed-861d-0242ac120002
    Groups            [students teachers system:authenticated]
    Extra: skills     [reading learning]
    Extra: subjects   [math sports]
    ```
output 플래그를 제공함으로써 결과의 JSON 또는 YAML 표현을 출력하는 것도 가능한다.

{{< tabs name="self_subject_attributes_review_Example_1" >}}
{{% tab name="JSON" %}}
```json
{
  "apiVersion": "authentication.k8s.io/v1alpha1",
  "kind": "SelfSubjectReview",
  "status": {
    "userInfo": {
      "username": "jane.doe",
      "uid": "b79dbf30-0c6a-11ed-861d-0242ac120002",
      "groups": [
        "students",
        "teachers",
        "system:authenticated"
      ],
      "extra": {
        "skills": [
          "reading",
          "learning"
        ],
        "subjects": [
          "math",
          "sports"
        ]
      }
    }
  }
}
```
{{% /tab %}}

{{% tab name="YAML" %}}
```yaml
apiVersion: authentication.k8s.io/v1alpha1
kind: SelfSubjectReview
status:
  userInfo:
    username: jane.doe
    uid: b79dbf30-0c6a-11ed-861d-0242ac120002
    groups:
    - students
    - teachers
    - system:authenticated
    extra:
      skills:
      - reading
      - learning
      subjects:
      - math
      - sports
```
{{% /tab %}}
{{< /tabs >}}

이 기능은 쿠버네티스 클러스터에서 복잡한 인증 흐름이 사용되는 경우에 매우 유용한다. 예를 들어, 
[웹훅 토큰 인증](/docs/reference/access-authn-authz/authentication/#webhook-token-authentication) 또는 [인증 프록시](/docs/reference/access-authn-authz/authentication/#authenticating-proxy)와 같은 인증 방법을 사용하는 경우이다. 
이러한 경우 결과를 JSON 또는 YAML 형식으로 출력하여 인증에 대한 세부 정보를 쉽게 확인할 수 있다.

{{< note >}}
쿠버네티스 API 서버는 유저 인증을 포함하여 모든 인증 메커니즘이 적용된 후에 userInfo를 채운다. 
따라서 인증 대리 또는 인증 프록시가 인증을 위해 SelfSubjectReview를 실행하는 경우, 특정 
사용자를 [가장한(impersonation)](/docs/reference/access-authn-authz/authentication/#user-impersonation) 사용자에 대한 사용자 세부 정보와 속성을 확인할 수 있다. 
이를 통해 impersonation이 적용된 사용자의 식별 정보를 확인할 수 있다.
{{< /note >}}

기본적으로, `APISelfSubjectReview` 기능이 활성화되어 있는 경우 모든 인증된 사용자는 
`SelfSubjectReview` 오브젝트를 생성할 수 있다. 이러한 권한은 `system:basic-user` 
클러스터 역할에 의해 허용된다.

{{< note >}}
`SelfSubjectReview` 요청을 만들 수 있는 경우는 다음과 같다:
* 클러스터에 APISelfSubjectReview [기능 게이트](/docs/reference/command-line-tools-reference/feature-gates/)가 활성화되어 있는 경우 (베타 버전 달성 후 기본적으로 활성화됨).  
* 클러스터의 API 서버가 `authentication.k8s.io/v1alpha1` 또는 `authentication.k8s.io/v1beta1 API` 그룹을 활성화한 경우
  {{< glossary_tooltip term_id="api-group" text="API group" >}}
{{< /note >}}



## {{% heading "whatsnext" %}}

* [클라이언트 인증 레퍼런스 (v1beta1)](/docs/reference/config-api/client-authentication.v1beta1/)
* [클라이언트 인증 레퍼런스 (v1)](/docs/reference/config-api/client-authentication.v1/)


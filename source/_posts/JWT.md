---
layout:     post
title:      "JWT深入讲解与Java项目实战（附源码)"
date:       2020-12-10 12:00:00
author:     "佘黎明"
# header-img: "post-bg-2015.jpg"
tags:
    - SSO
    - 微信小程序
---

## 一、JWT是什么

JWT全称Json Web Token，它是一个开放的标准，它定义了一种紧凑且自包含的方式，用于在各方之间安全地将信息作为JSON对象传输。 由于此信息是经过数字签名的，因此可以被验证和信任。

这是官网（https://jwt.io/introduction/）对JWT的定义，个人简单的理解：JWT定义了一系列的算法将需要传输的数据进行加密生成一个token（令牌，也就是一个字符串），只要你有密钥就可以在任何地方验证token的合法性并取出token中的数据。

## 二、JWT产生的原因

### 传统的session认证：

我们知道，http协议本身是一种无状态的协议，而这就意味着如果用户向我们的应用提供了用户名和密码来进行用户认证，那么下一次请求时，用户还要再一次进行用户认证才行，因为根据http协议，我们并不能知道是哪个用户发出的请求，所以为了让我们的应用能识别是哪个用户发出的请求，我们只能在服务器存储一份用户登录的信息，这份登录信息会在响应时传递给浏览器，告诉其保存为cookie，以便下次请求时发送给我们的应用，这样我们的应用就能识别请求来自哪个用户了，这就是传统的基于session认证。

传统的Session认证有一个明显的弊端，就是服务端需要存储所有用户的登录信息，这样当用户量非常大的时候服务端的压力就会很大（当然也有一系列的分布式session的方案）。所以就有一种基于token的鉴权机制被发明：

### 基于token的鉴权机制：

首先用户向服务器发送用户名密码的鉴权信息，服务器根据JWT的规则生成一个token，这个token包含用户的信息和签名的信息，用户拿到这个token保存在本地，以后发请求的时候都带上这个token，服务端根据token可以验证token的合法性并解析出用户的信息，这样就可以识别出是哪个用户了。

那么这个token怎么被生成呢？

## 三、JWT的结构

JWT分为三个部分：header、playload、signature。

#### header：头部

头部一般都是固定两个字段：

typ：声明类型，一般JWT

alg：声明加密算法，一般使用HMAC SHA256

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

然后将这个Json字符串进行base64编码（这种加密是对称的，可以直接进行解密）构成第一部分:

可以在网站上在线加密：https://tool.oschina.net/encrypt?type=3

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

#### playload：存放有效信息的地方

**1、标准中注册的声明 (建议但不强制使用) ：**

`iss`: jwt签发者

`sub`: jwt所面向的用户

`aud`: 接收jwt的一方

`exp`: jwt的过期时间，这个过期时间必须要大于签发时间

`nbf`: 定义在什么时间之前，该jwt都是不可用的.

`iat`: jwt的签发时间

`jti`: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。

**2、公共的声明 ：**

公共的声明可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息.但不建议添加敏感信息，因为该部分在客户端可解密。

**3、私有的声明 ：**

私有声明是提供者和消费者所共同定义的声明，一般不建议存放敏感信息，因为base64是对称解密的，意味着该部分信息可以归类为明文信息。

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

然后将其进行base64加密，得到Jwt的第二部分:

```
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
```

#### signature：签名信息

这个部分需要base64加密后的header和base64加密后的payload使用.连接组成的字符串，然后通过header中声明的加密方式进行加盐secret组合加密

最后将这三部分用.连接成一个完整的字符串,构成了最终的jwt:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

## 四、Java实现JWT

基于以上原理，我们调用一些jdk自带的包，就可以基于以上规则生成JWT的token。

```java
package com.mj.time.util;

import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Test {
    public static String Hmacsha256(String secret, String message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac_sha256 = Mac.getInstance("HMacSHA256");
        SecretKeySpec key = new SecretKeySpec(secret.getBytes(), "HMacSHA256");
        hmac_sha256.init(key);
        byte[] buff = hmac_sha256.doFinal(message.getBytes());
        return Base64.encodeBase64URLSafeString(buff);
    }

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException {
        String secret = "secret123";
        String header = "{\"type\":\"JWT\",\"alg\":\"HS256\"}";
        String claim = "{\"sub\": \"1234567890\",\"name\": \"John Doe\",\"iat\":1516239022}";

        String base64Header = Base64.encodeBase64URLSafeString(header.getBytes());
        String base64Claim = Base64.encodeBase64URLSafeString(claim.getBytes());
        String signature = Hmacsha256(secret, base64Header + "." + base64Claim);

        String jwt = base64Header + "." + base64Claim  + "." + signature;
        System.out.println(jwt);
    }
}
```

明显这样生成token非常麻烦，很容器出错，所以就有一系列的第三方库支持，各种语言都有。可以看官网上列的：https://jwt.io/#libraries-io

## 五、开源库 jjwt 实现 JWT

jjwt是目前使用比较多，支持加密算法比较多的Java库。github有7000+star。比官方的库java-jwt的3000+star多了一倍多。所以我们使用jjwt作为我们的例子：

源码的github地址：https://github.com/jwtk/jjwt

### 1、基本使用

**1、引入pom依赖**

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.2</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.2</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.2</version>
    <scope>runtime</scope>
</dependency>
```

**2、生成JWTtoken**

```java
Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
String jws = Jwts.builder().setSubject("Joe").signWith(key).compact();
```

执行后生成的jws为：

`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJKb2UifQ.jObJ_3Y_mXHg2vlyvYQQH3RRZlwZvtrvoZnKts3Aq58`

哈哈，只要两行代码，创建一个token。这个token使用HMAC-SHA-256进行签名，并设定了标准中注册的声明`sub`的值为`Joe`

**3、校验token及获取内容**

```java
try{
		String subject = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jws).getBody().getSubject();
  	//token合法，进行后续操作
} catch (JwtException e) {
    //token不可信
}
```

如果传入的token是合法的，subject就可以拿到之前放入的`Joe`。如果token被修改或者失效，就会抛出JwtException。

### 2、签名算法及密钥介绍

在介绍jjwt详细使用之前，我们先介绍一下和jwt相关的签名算法和密钥，了解它们对正确创建jwt至关重要。

JWT规范标识了12种标准签名算法-3种密钥算法和9种非对称密钥算法：

- `HS256`: HMAC using SHA-256
- `HS384`: HMAC using SHA-384
- `HS512`: HMAC using SHA-512
- `ES256`: ECDSA using P-256 and SHA-256
- `ES384`: ECDSA using P-384 and SHA-384
- `ES512`: ECDSA using P-521 and SHA-512
- `RS256`: RSASSA-PKCS-v1_5 using SHA-256
- `RS384`: RSASSA-PKCS-v1_5 using SHA-384
- `RS512`: RSASSA-PKCS-v1_5 using SHA-512
- `PS256`: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
- `PS384`: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
- `PS512`: RSASSA-PSS using SHA-512 and MGF1 with SHA-512

这些算法其实对我们程序员来说并不重要，我们只要选择合适的算法即可。但是我们需要注意一下密钥的选择。JWT规范中要求必须使用对于所选算法足够强的密钥。所以jjwt还将强制你为选择的算法使用足够强大的密钥。 如果为给定算法提供弱密钥，JJWT将拒绝它并抛出异常。

当然jjwt为了让你能不需要了解算法就可以生成合法的密钥，jjwt提供了工具类`io.jsonwebtoken.security.Keys`。我们可以使用这个工具类生成对应算法的正确最小长度的安全随机密钥，然后保存起来，后面就可以当作加密的密钥了。

```java
SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256); //or HS384 or HS512
String secretString = Encoders.BASE64.encode(key.getEncoded());
```

还支持非对称加密的公私钥生成：

```java
KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256); 
//or RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512
keyPair.getPrivate()//私钥
keyPair.getPublic()//公钥
```

可以使用私钥创建一个JWS，并使用公钥来解析/验证JWS。

### 3、详细使用

创建一个JWS分为以下4个步骤：

1、使用Jwts.builder（）方法创建JwtBuilder实例。

2、调用JwtBuilder方法以根据需要添加标头参数和声明。

3、指定要用于对JWT签名的SecretKey或非对称PrivateKey。 

4、最后，调用compact（）方法进行压缩和签名，生成最终的jws。

```java
String jws = Jwts.builder() // (1)
    .setSubject("Bob")      // (2) 
    .signWith(key)          // (3)
    .compact();             // (4)
```

下面针对每一个可以扩展的点进行详细说明：

#### Header Parameters

JWT的header提供内容、格式、加密算法的元数据，如果想增加header的数据，可以调用`JwtBuilder` 的`setHeaderParam`方法一次或多次来添加Header：

```java
String jws = Jwts.builder()
    .setHeaderParam("kid", "myKeyId")
    .setHeaderParam("","")
    // ... etc ...
```

#### Claims

Claims是JWT的主体，并包含JWT创建者希望提供给JWT接收者的信息。

JWT提供了一些标准的Claims：jjwt都提供了标准的方法设置：

- `setIssuer`: sets the [`iss` (Issuer) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.1)
- `setSubject`: sets the [`sub` (Subject) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.2)
- `setAudience`: sets the [`aud` (Audience) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.3)
- `setExpiration`: sets the [`exp` (Expiration Time) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.4)
- `setNotBefore`: sets the [`nbf` (Not Before) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.5)
- `setIssuedAt`: sets the [`iat` (Issued At) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.6)
- `setId`: sets the [`jti` (JWT ID) Claim](https://tools.ietf.org/html/rfc7519#section-4.1.7)

```java
String jws = Jwts.builder()
    .setIssuer("me")
    .setSubject("Bob")
    .setAudience("you")
    .setExpiration(expiration) //a java.util.Date
    .setNotBefore(notBefore) //a java.util.Date 
    .setIssuedAt(new Date()) // for example, now
    .setId(UUID.randomUUID()) //just an example id
    /// ... etc ...
```

使用自定义的Claims：

```java
String jws = Jwts.builder()
    .claim("hello", "world")
    // ... etc ...
```

#### Signing Key

建议使用 `JwtBuilder`的`signWith`方法设置密钥，因为当你的密钥长度不满足算法的要求的时候，jjwt会自动给你改成对密钥长度要求低的加密算法。并且该方法还会给你设置header中的加密算法。

```java
String secretString = "XXXXXXXXXX";
SecretKey secretKey = Keys.hmacShaKeyFor(secretString.getBytes(StandardCharsets.UTF_8));
String jws = Jwts.builder()

   .signWith(secretKey) // <---
   .compact();
```

#### 解析JWS

```java
Jws<Claims> jws;

try {
    jws = Jwts.parserBuilder()  // (1)
    .setSigningKey(key)         // (2)
    .build()                    // (3)
    .parseClaimsJws(jwsString); // (4)
    
    // we can safely trust the JWT
     
} catch (JwtException ex) {       // (5)
    
    // we *cannot* use the JWT as intended by its creator
}
```



## 六、Springboot项目实战源码

项目实战就是将第二节中的“基于token的鉴权机制”，使用Java代码实现。

#### 1、封装工具类

封装JwtTokenUtils，主要包括生成token、校验token和解析token三个方法。

```java
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

@Component
@Slf4j
public class JwtTokenUtils {
    /**
     * 秘钥
     */
    @Value("${jwt.secret:52GLLfnJ30xJ0qCBgPMVUOatf4BUJvGMejJzXD418HQ=}")
    private String secret;
    /**
     * 有效期，单位秒
     * - 默认2周
     */
    @Value("${jwt.expire-time-in-second:1209600}")
    private Long expirationTimeInSecond;

    /**
     * 为指定用户生成token
     *
     * @param claims 用户信息
     * @return token
     */
    public String createToken(Map<String, Object> claims) {
        Date createdTime = new Date();
        Date expirationTime = this.getExpirationTime();

        byte[] keyBytes = secret.getBytes();
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        String token = Jwts.builder()
                .setClaims(claims)               //设置自定义属性
                .setIssuedAt(createdTime)        //设置token创建时间
                .setExpiration(expirationTime)   //设置token过期时间
                .signWith(key, SignatureAlgorithm.HS256)  //// 支持的算法详见：https://github.com/jwtk/jjwt#features
                .compact();

        return token;
    }

    /**
     * 校验token
     * @param token
     * @return
     */
    public Boolean verifyToken(String token) {
        byte[] keyBytes = secret.getBytes();
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException ex) {
            log.error("token:{},验证失败", token, ex);
            return false;
        }
    }

    /**
     * 从token中获取claim
     *
     * @param token token
     * @return claim
     */
    public Claims getClaimsFromToken(String token) {
        byte[] keyBytes = secret.getBytes();
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            Claims claims = jws.getBody();
            return claims;
        } catch (JwtException ex) {
            log.error("token:{},验证失败", token, ex);
            throw new RuntimeException("token验证失败");
        }
    }

    /**
     * 生成随机合法密钥，然后手动保存到配置文件。密钥千万不能泄漏！！！
     *
     * @return
     */
    public String generateSecretString() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256); //or HS384 or HS512
        String secretString = Encoders.BASE64.encode(key.getEncoded());
        return secretString;
    }

    public static void main(String[] args) {
        System.out.println(new JwtTokenUtils().generateSecretString());
    }

    /**
     * 计算token的过期时间
     *
     * @return 过期时间
     */
    private Date getExpirationTime() {
        return new Date(System.currentTimeMillis() + this.expirationTimeInSecond * 1000);
    }
}
```

springboot配置文件中增加以下配置，没有配置的话会使用默认值：其中密钥可以用generateSecretString方法生成一个随机合法密钥。

```yaml
jwt:
  secret: 52GLLfnJ30xJ0qCBgPMVUOatf4BUJvGMejJzXD418HQ=
  expire-time-in-second: 1209600
```

#### 2、增加NoNeedToken注解

默认所有接口都需要校验token，@NoNeedToken注解用来表示接口不需要校验token，例如登录接口和一些公共接口。

```java
import java.lang.annotation.*;

@Target({ElementType.METHOD, ElementType.TYPE}) //注解的范围是类、接口、枚举的方法上
@Retention(RetentionPolicy.RUNTIME)//被虚拟机保存，可用反射机制读取
@Documented
public @interface NoNeedToken {
}
```

#### 3、配置过滤器

编写token校验过滤器，

```java
import com.alibaba.fastjson.JSONObject;
import com.mj.time.annotation.NoNeedToken;
import com.mj.time.common.ErrorCodeEnum;
import com.mj.time.util.JwtTokenUtils;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

@Component
public class TokenInterceptor implements HandlerInterceptor {
    @Autowired
    private JwtTokenUtils jwtTokenUtils;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 设置返回值属性
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        String token = request.getHeader("token");
        PrintWriter out;
        // 对于注解的判断
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        if (handlerMethod.getMethodAnnotation(NoNeedToken.class) != null || handlerMethod.getBeanType().isAnnotationPresent(NoNeedToken.class)) {
            // 如果方法拥有NoNeedToken标注或者所属的类拥有NoNeedToken 就直接放行
            return true;
        }

        if (StringUtils.isEmpty(token)) {
            JSONObject res = new JSONObject();
            res.put("code", ErrorCodeEnum.TOKEN_ERROR.getCode());
            res.put("message", ErrorCodeEnum.TOKEN_ERROR.getMsg());
            out = response.getWriter();
            out.append(res.toString());
            return false;
        }

        Claims claims = null;
        try {
            claims = jwtTokenUtils.getClaimsFromToken(token);
        } catch (Exception ignored) {
            //解析token失败
            JSONObject res = new JSONObject();
            res.put("code", ErrorCodeEnum.TOKEN_ERROR.getCode());
            res.put("message", ErrorCodeEnum.TOKEN_ERROR.getMsg());
            out = response.getWriter();
            out.append(res.toString());
            return false;
        }
        //将token中解析出来的信息放入attribute中
        if (claims != null) {
            request.setAttribute("user_claims", claims);
            return true;
        }

        return false;
    }
}
```

配置过滤器，默认将所有的请求拦截：

```java
import com.mj.time.intercepter.TokenInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.Resource;

@Configuration
public class InterceptorConfig  implements WebMvcConfigurer {
    @Resource
    TokenInterceptor tokenInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 设置所有的路径都要进行拦截
        registry.addInterceptor(tokenInterceptor).addPathPatterns("/**");
    }
}
```

#### 4、编写BaseController

所有的contoller需要继承BaseController，BaseController主要解析Attribute中的user_claims获取用户信息。

```java
import com.mj.time.common.Constants;
import io.jsonwebtoken.Claims;
import org.springframework.web.bind.annotation.ModelAttribute;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BaseController {
    protected HttpServletRequest request;
    protected HttpServletResponse response;
    protected Integer userId;  // 用户id
    protected String authType; // 登录类型

    @ModelAttribute
    public void parseClaims(HttpServletRequest request, HttpServletResponse response) {
        this.request = request;
        this.response = response;
        // 获取到在拦截器里设置的 user_claims， 并将其保存到类的成员变量中
        Claims userClaims = (Claims) request.getAttribute("user_claims");
        if (userClaims != null) {
            this.userId = (Integer) userClaims.get(Constants.CLAIMS_USER_ID);
            this.authType = (String) userClaims.get(Constants.CLAIMS_AUTH_TYPE);
        }
    }
}
```

#### 5、登录接口

登录接口加上@NoNeedToken注解，因为登录的时候还没有token，调用登录接口获取token。

```java
import com.mj.time.annotation.NoNeedToken;
import com.mj.time.common.CommonResponse;
import com.mj.time.service.AuthService;
import com.mj.time.service.dto.AuthLoginDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/time/auth")
@NoNeedToken
public class AuthController {
    @Autowired
    private AuthService authService;

    @PostMapping(value = "/login")
    public CommonResponse<AuthLoginDto> login(@RequestBody AuthLoginDto authLoginDto) {
        AuthLoginDto authLoginDtoResp = authService.login(authLoginDto);
        return new CommonResponse<AuthLoginDto>(authLoginDtoResp);
    }
}
```

实现就是先去数据库判断用户名密码对不对，如果正确使用userId去创建一个token放入返回中。

```java
@Override
public AuthLoginDto login(AuthLoginDto authLoginDto) {
  User user = userMapper.selectByUserNameOrMobile(authLoginDto.getUserNameOrMobile());
  if (user == null || !user.getPassword().equals(authLoginDto.getPassword())) {
    throw new BizException(ErrorCodeEnum.USERNAME_OR_PASSWORD_ERROR);
  } else {
    authLoginDto.setUserInfo(user);

    Map<String, Object> claims = new HashMap<>();
    claims.put(Constants.CLAIMS_USER_ID, user.getId());
    claims.put(Constants.CLAIMS_AUTH_TYPE, AuthTypeEnum.PASSWORD.getValue());
    String token = jwtTokenUtils.createToken(claims);
    authLoginDto.setToken(token);
  }
  return authLoginDto;
}
```

调用结果：我们可以获取到一个token

![image-20201209195520846](image-20201209195520846.png)

#### 6、需要鉴权接口

无需任何改变，默认所有接口都需要鉴权：

```java
@RestController
@RequestMapping("/api/time/tag")
public class TagController extends BaseController {
    @Autowired
    private TagService tagService;
  
    @GetMapping
    CommonResponse<List<Tag>> getAllMenu() {
        List<Tag> tagList = tagService.selectUserTagList(this.userId);
        return new CommonResponse<List<Tag>>(tagList);
    }
}

```

如果在Headers中没有传入token：调用失败

![image-20201209195709567](image-20201209195709567.png)

传入token之后：调用成功

![image-20201209195746076](image-20201209195746076.png)

#### 

## 七、结语

至此、我们已经了解JWT的原理、jjwt库的使用以及项目中的应用。赶紧自己去实验一下吧。

以上所展示的源码地址：https://github.com/shelimingming/time_manage/tree/main/time_manage_backend
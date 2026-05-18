# 🧠 1. 工具用途（安全领域做什么）

这是一个 **Webshell 扫描与检测工具（Webshell Detector）**，核心用途是：

👉 在大量 URL（目录 × 文件字典）中自动探测可能存在的 Webshell（后门脚本）

### 🎯 安全领域定位：

* Web安全渗透测试（PT）
* 红队资产扫描
* 蓝队恶意文件检测
* 批量目录爆破 + 内容分析
* 攻防对抗中的后门识别

### 🧨 检测目标：

* PHP Webshell（WSO / C99 / b374k / r57 等）
* 代码执行后门（eval/system/exec）
* 文件管理器类后门
* 上传型 Webshell 页面


# 🔄 2. 工作流程（输入 → 输出）

## 📥 输入

* `--directories`：目录列表（例如 `/admin/`, `/upload/`）
* `--dictionary`：文件字典（如 `shell.php`, `cmd.php`）

## ⚙️ 执行流程

### 🧩 Step 1：组合目标

```
directory × filename
↓
生成 URL 列表
```

### 🚀 Step 2：Producer（生产者）

* 随机打乱所有目标
* 放入 asyncio queue


### 👷 Step 3：Worker（多协程扫描）

每个 worker：

```
取 queue → check_url()
```


### 🌐 Step 4：HTTP 检测流程

#### 1️⃣ HEAD 预检

* 判断是否可能存在页面
* 降低 GET 请求压力

#### 2️⃣ GET 请求

* 获取 HTML 内容（最大 2MB）

#### 3️⃣ 过滤阶段

* Content-Type 过滤
* WAF / Cloudflare 检测
* 错误页 hash 去重
* 大小限制过滤


### 🧠 Step 5：风险评分引擎

调用：

```
calculate_risk(content)
```

输出：

```
score + risk_level + matched_fingerprint
```


### 🚨 Step 6：结果输出

满足条件：

```
score >= min_score AND matched >= 2
```

写入：

* found_webshells.txt（结果）
* findings_verbose.log（详细分析）


# 🧩 3. 关键模块解析


## 🔍 (1) 扫描模块

### ✔ 组合扫描

```python
targets = [(dir, file) for dir in directories for file in filenames]
```

👉 典型 **爆破式 Webshell 扫描**


## 🌐 (2) 请求模块（aiohttp）

* async HTTP GET/HEAD
* TCP 连接池
* keep-alive
* SSL verify disabled（⚠️）

```python
aiohttp.TCPConnector(limit=600, ssl=False)
```

👉 高并发扫描核心


## ⚖️ (3) 过滤模块

### 内容过滤：

* Content-Type 白名单
* 最大响应大小限制
* 错误页面识别（hash）

### WAF识别：

```
cloudflare / captcha / sucuri / access denied
```


## 🧠 (4) 规则引擎（核心）

### 🔥 fingerprint（高危特征）

```python
wso / c99 / b374k / r57
```

→ 一命中直接 CRITICAL = 100分


### 🔥 regex 规则

```python
system(
exec(
eval(
base64_decode(
gzinflate(
```


### 🔥 UI特征

* textarea + cmd/shell
* upload/file manager


## 📊 (5) 自适应并发控制

### 📉 降速条件：

* 429 > 7%
* 403 > 12%

👉 自动降低并发


### 📈 提速条件：

* 200 成功率 > 78%

👉 自动提升并发


## 🧵 (6) 并发架构

### 使用：

* asyncio
* Semaphore（全局 + host级）
* Queue
* Task workers


### 并发结构：

```
Producer → Queue → Workers → HTTP check
```


# 🧷 4. 命令行参数说明

```bash
--directories / -d     目录文件
--dictionary / -w      文件字典
--output / -o          输出文件
--min-score           最低风险分数（默认55）
--concurrency / -c    worker数量（默认150）
--global-limit        全局并发限制（默认220）
--allow-redirect      是否允许跳转
```


# 📥 5. 输入 / 输出示例


## 📌 输入

### directories.txt

```
/admin/
/upload/
/assets/
```

### dictionary.txt

```
shell.php
cmd.php
wso.php
index.php
```

## 🚀 执行

```bash
python3 detector.py -d directories.txt -w dictionary.txt
```


## 📤 输出

### found_webshells.txt

```
http://target.com/admin/shell.php
http://target.com/upload/cmd.php
```


### verbose.log

```
URL: http://target.com/admin/shell.php
Score: 92 | Risk: CRITICAL
Matched: REGEX×3, PHP_MULTI×1.65
```



# ⚡ 6. 性能 / 并发机制


## 🧵 async 架构

* asyncio event loop
* non-blocking HTTP


## 📦 Queue模型

* maxsize=15000
* 防止内存爆炸


## ⚖️ Semaphore控制

### 双层控制：

```
global_semaphore
host_semaphores
```

👉 防止：

* 单目标打爆服务器
* 单 host flood


## 📊 Adaptive机制

动态调整：

* 并发数
* 根据状态码分布


## 🚀 优化点：

* TCP连接复用
* DNS cache
* random UA
* request jitter


# ⚠️ 7. 风险提示（非常重要）

## 🚨 (1) 误报风险

可能误判：

* CMS页面（WordPress插件）
* 管理后台
* 文件上传页面


## 🚨 (2) WAF误伤

Cloudflare / Sucuri：
→ 会导致大量 false negative


## 🚨 (3) 高并发风险

默认：

```
concurrency=150
global_limit=220
```

可能导致：

* IP被封
* rate limit
* 403/429


## 🚨 (4) 安全风险（合法性）

⚠️ 如果用于未授权目标：

* 属于非法扫描行为
* 可能违反当地网络法律


## 🚨 (5) 稳定性问题

* SSL disabled（风险）
* large queue（内存压力）


# 🛠️ 8. 如何部署和使用（Step-by-step）


## 🧩 Step 1：安装依赖

```bash
git clone https://github.com/Michael-TopKing/Webshell-Checker-V3.git
cd Webshell-Checker-V3
pip3 install -r requirements.txt
```


## 🧩 Step 2：准备文件

```
directories.txt
dictionary.txt
```

## 🧩 Step 3：运行扫描

```bash
python3 webshell_detector.py \
  -d directories.txt \
  -w dictionary.txt \
  -o found_webshells.txt \
  -c 150
```


## 🧩 Step 4：查看结果

```
found_webshells.txt
findings_verbose.log
```


## 🧩 Step 5（可选优化）

降低误封：

```bash
--min-score 65
```




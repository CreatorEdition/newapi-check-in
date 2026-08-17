# NewAPI 签到优化任务

状态：🔄 进行中

## API 优先增量任务（2026-08-17）

1. 增加 `api_key`/`jwt` 令牌配置，按 `api_key → jwt → cookies` 优先级调用 NewAPI。
2. 令牌和 Cookies API 请求失败后，才按 WAF Cookie、邮箱密码浏览器顺序恢复。
3. 补充 API-first 离线测试与 README 配置说明。

## 本轮范围

1. 修复 CI 中浏览器 Profile 持久化、账号串号和敏感代理日志问题。
2. 统一 NewAPI 请求/响应处理，支持 `sign_in -> checkin` 回退及明确结果分类。
3. 修复 WAF Cookie 合并、HTTP/2 请求头、配置校验和通知配置容错。
4. 增加 GitHub Actions 并发保护与质量检查可靠性。
5. 补充离线单元测试，并同步 README 使用说明。

## 验收标准

- 不在日志、缓存或测试输出中暴露 Cookie、Token、密码或完整代理 URL。
- `sign_in` 请求为空 body 且不带 JSON Content-Type；失败时可回退 `checkin`。
- 401/403、WAF HTML、已签到、签到关闭和普通失败可区分。
- 现有测试与新增测试通过；无法在本地运行的命令必须明确记录。
- 完成后更新为：✅ 已完成，并记录剩余未验证风险。

## 验证记录

- ✅ Python `compileall` 通过。
- ✅ NewAPI 适配层、配置校验和代理脱敏离线 smoke test 通过。
- ✅ 旧油猴脚本 Node 回归测试通过（146 项）。
- ✅ `git diff --check` 通过。
- ✅ 使用官方 Ruff 0.12.11 二进制复核，格式与 lint 均通过。
- ✅ GitHub Actions `PR Quality Checks` run `31977284606` 通过：Ruff、格式、MyPy、Bandit、Pytest 全部通过（40 passed、1 skipped）。
- ⚠️ 当前 Windows 环境无法从 PyPI 下载完整依赖，本地未重复完整 Python 门禁；以 Actions Linux 结果为准。
- ✅ CloakBrowser 安装修复已由 run `31973407249` 验证成功。
- ⚠️ 未执行真实站点登录、签到、代理或通知请求，避免触碰用户登录态和外部服务。

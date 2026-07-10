# Issue #92 Code Review Agent 重构设计

## 背景

当前分支已经具备 code-review Skill、八个公开 fixture、SQLite 存储、JSON/Markdown 报告、Filter 和基础 Telemetry，但审查发现安全边界、失败语义、输入解析和验收证据仍存在缺口。最严重的问题包括：SkillRun 的 inputs/cwd/outputs 未进入 Filter 决策、部分秘密可明文进入报告和数据库、needs_human_review 后仍自动执行 local、Container 启动失败被记录为 completed 且 failures=0，以及 sandbox 低置信结果绕过去噪逻辑。

本设计采用五阶段小 PR 重构，每个 PR 必须可独立合并、回滚，并保持相关测试通过。

## 目标

- 满足 Issue #92 的九项能力、输入输出要求和八条验收标准。
- 在文件暂存或命令执行前完成完整的安全判断。
- 保证原始秘密不会进入 Sandbox、日志、报告或数据库。
- 让 task、SandboxRun、Telemetry、报告结论表达同一个事实。
- 统一 host 与 sandbox findings 的 schema、置信度路由和去重规则。
- 通过真实 Container、超时、输出限制和指标测试提供可复现验收证据。

## 非目标

- 不在本轮加入真实 LLM 推理或网络模型调用。
- 不扩展 Issue #92 未要求的新规则类别。
- 不重构 Claude、OpenClaw 或其他无关服务。
- 不在默认生产路径提供未经批准的 local 自动降级。

## 总体架构

主数据流固定为：

InputResolver → RedactionBoundary → PolicyGate → SandboxExecutor → ResultNormalizer → ReviewStorage → ReportBuilder

各组件职责如下：

- InputResolver：解析 diff-file、repo-path、带仓库根目录的 file-list 和 fixture，输出统一的 ResolvedReviewInput。
- RedactionBoundary：处理输入、异常、日志、artifact、DSN 和报告字段；原始值只允许短暂存在于进程内存。
- PolicyGate：校验完整 ExecutionRequest，并在任何输入暂存或程序执行前返回 allow、deny 或 needs_human_review。
- SandboxExecutor：只执行 allow 请求，负责真实超时终止、流式输出限制和 SandboxRun 记录。
- ResultNormalizer：把所有来源的结果统一执行 schema 校验、再次脱敏、confidence routing 和去重。
- ReviewStorage：持久化任务状态、输入摘要、Filter 决策、SandboxRun、finding、Telemetry 和最终报告。
- ReportBuilder：只从规范化、已持久化的最终状态构建 JSON 和 Markdown。

## 五阶段交付边界

### PR0：分支清理

- Rebase 最新 upstream main。
- 移除 Claude、OpenClaw、无关依赖固定和其他与 Issue #92 无关的修改。
- 单独保留示例目录和确有必要的 Container path 修复。
- 确认 merge-tree、测试和工作树状态干净。

### PR1：安全边界

- 引入不可变 ExecutionRequest，字段包含 runtime、command argv、cwd、inputs、outputs、env、network、timeout 和预算。
- PolicyGate 校验完整请求；inputs 只允许读取本次生成的 review JSON，目标只能位于 work/inputs。
- 禁止绝对目标、路径穿越、受保护宿主路径、覆盖 Skill 脚本、非白名单网络和环境变量。
- dummy、test、example 仅影响 finding 置信度，不得关闭脱敏。
- 所有持久化出口执行最终脱敏，数据库 DSN 隐藏用户名密码。

### PR2：执行状态机与审计

任务状态为：

- created：输入已解析并保存。
- running：开始 Filter 和 Sandbox 编排。
- completed：所有必要检查执行完成。
- completed_with_errors：报告已生成，但存在 Sandbox 超时、非零退出或 artifact 错误。
- blocked：deny 或 needs_human_review 阻止了必要检查。
- failed：编排、存储或报告生成发生不可恢复错误。

每次 Filter 判断立即落库。allow 后无论启动失败、超时、非零退出或输出超限，都必须生成 SandboxRun。每个 SandboxRun 完成后立即保存；最终报告和 terminal status 在同一个事务中写入。

FilterIntercept 的 intercept_id 必须包含 task_id 和 request_id 参与计算，保证 dry-run 可复现且跨任务全局唯一；task_id 建立索引和外键。报告结论优先反映 terminal status，blocked、failed 或 completed_with_errors 不得显示为无问题。

### PR3：输入与结果规范化

- 标准 unified diff 不再要求 diff --git 头。
- repo-path 合并 staged、unstaged 和 untracked 变更。
- file-list 成为明确输入模式，不得隐式加载 fixture。它必须与 repo-path 一起使用：以 repo-path 为根目录，将列表作为 git diff 的路径选择器，并为选中的 untracked 文件生成新增文件补丁；缺少 repo-path 时直接返回参数错误。
- 所有 host 与 sandbox findings 进入同一个 ResultNormalizer。
- confidence 大于等于 0.80 进入 findings；0.50 至 0.79 进入 warnings 或 needs_human_review；低于 0.50 丢弃并计入 debug 指标。
- 去重键固定为 file、line、category；保留最高严重度和最高置信度结果，并合并 source。

### PR4：资源限制与验收

- stdout、stderr 和 artifact 使用流式读取；超过字节上限立即停止读取并终止相应执行。
- 超时后必须 kill 进程或 Container exec，并确认不再运行。
- Container 配置 CPU、内存、PID、网络和临时磁盘限制。
- Telemetry 记录总耗时、Sandbox 总耗时、工具尝试数、实际执行数、拦截数、finding 数、severity 分布、异常类型分布、截断数和脱敏数。
- CI 覆盖 examples、Skill scripts、tests 和相关 SDK 文件的 pytest、flake8、YAPF 与 git diff --check。

## 数据模型

### ResolvedReviewInput

- input_type
- input_ref_redacted
- diff_text_redacted
- changed_files
- hunks
- candidate_lines
- fixture_names

### ExecutionRequest

- request_id
- task_id
- runtime
- command_argv
- cwd
- input_specs
- output_specs
- env
- network_access
- timeout_seconds
- output_budget_bytes

### SandboxRun

- run_id
- task_id
- request_id
- runtime
- decision
- exit_code
- timed_out
- failure_kind
- failure_reason_redacted
- duration_ms
- stdout/stderr 与截断标志
- output 摘要与字节数

### NormalizedReviewResult

- findings
- warnings
- needs_human_review
- dropped_count
- validation_errors

## 错误分类

统一错误类别为：

- policy_denied
- approval_required
- runtime_unavailable
- execution_timeout
- execution_nonzero
- output_limit_exceeded
- artifact_invalid
- storage_error
- orchestration_error

异常文本在生成 ReviewWarning、SandboxRun 或日志之前必须经过 RedactionBoundary。

## 测试策略

### 单元测试

- PolicyGate 覆盖恶意 inputs、cwd、outputs、env、network、timeout 和预算。
- SecretRedactor 覆盖 passwd、client_secret、Bearer、DSN、JSON、camelCase、异常文本、含空格密码和 dummy 值。
- InputResolver 覆盖标准 unified diff、quoted path、staged、unstaged、untracked、带 repo-path 的 file-list，以及缺少 repo-path 时的参数错误。
- ResultNormalizer 覆盖 confidence 的 0、0.49、0.50、0.79、0.80 和 1.0 边界。
- 状态机覆盖全部合法转换并拒绝非法转换。

### 集成测试

- local 完整链路覆盖解析、规则、Sandbox、落库、报告和 task-id 查询。
- Container 不可用、超时、非零退出、artifact 损坏均留下 SandboxRun 和正确 terminal status。
- deny 与 needs_human_review 后，输入暂存和执行函数均未调用。
- 相同 Filter 决策跨 task 写入不发生主键冲突。

### 真实 Container 测试

Fake harness 用于快速回归；CI 中增加必须通过的 Docker 集成任务，验证 Skill 暂存、网络关闭、输入 containment、超时终止、流式输出限制、artifact 收集和报告落库。真实 Container 用例不能长期作为唯一 optional/skip 测试。

### 指标验收

- 八个公开 fixture 全部生成 JSON、Markdown 和数据库记录。
- 独立标注的高危数据集按位置和类别计算 recall，要求不低于 80%。
- 安全数据集按所有错误 findings 计算 false-positive rate，要求不高于 15%。
- 秘密格式语料计算脱敏 recall，要求不低于 95%，并扫描报告和数据库确认无明文。
- dry-run 使用墙钟断言完整流程小于 120 秒。
- 方案说明保持 300 至 500 个中文汉字，并由测试校验。

## 迁移与兼容

- SQLite schema 使用显式迁移添加 terminal status、failure_kind、request_id 和新的唯一约束。
- 旧数据库缺少新字段时只执行向前兼容迁移，不删除历史记录。
- JSON 报告 schema_version 升级，并为新状态、异常分布和执行尝试提供字段。
- CLI 保留现有 diff-file、repo-path、fixture、file-list、dry-run 和 runtime 参数；file-list 必须同时提供 repo-path，auto 不再隐式执行 local。

## 完成标准

- 五个 PR 均有独立测试和清晰提交历史。
- Issue #92 八条验收标准都有自动化测试或明确的真实环境验证命令。
- 不存在已知明文秘密持久化路径。
- blocked、failed、completed_with_errors 和 completed 的数据库、Telemetry、JSON 与 Markdown 表达一致。
- 工作树通过测试、格式、lint 和 whitespace 检查。

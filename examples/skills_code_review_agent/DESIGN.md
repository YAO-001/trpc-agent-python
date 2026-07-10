# 设计说明

本示例把自动代码审查拆成确定性核心和 Skill 执行层。输入解析器读取 unified diff、仓库 git diff 或 fixture，并在入库前先做密钥脱敏；规则引擎只处理新增行和必要上下文，按置信度把问题分为 finding、warning 与人工复核项。Skill 层通过 `SkillToolSet` 和 `skill_run` 在容器 workspace 中运行 stdlib-only 脚本，local 仅作为显式开发 fallback。所有命令在进入 sandbox 前先经过 `ReviewExecutionPolicy`，危险命令、敏感路径、越界输出、泄露型 env、网络和安装包请求会被拒绝或进入人工复核。sandbox stdout、stderr 与 output artifacts 再次执行截断和脱敏后才合并为 findings 并持久化。SQLite schema 按 task、input、sandbox_runs、findings、filter_intercepts、telemetry_summaries、reports 分表保存审计链路。dedupe 使用文件、行号、类别和规范化标题合并来源，降低噪声。telemetry 记录命中数、截断数、过滤拦截、sandbox 失败和脱敏数量，报告只暴露可复核证据与修复建议。

The core audit chain does not depend on a real model API; an LLM can be added later as a summarization layer, while the accepted deterministic dry-run path remains reproducible.

## 恶意流量检测系统

制作一个**基于****大模型的离线恶意流量检测系统**（SemFlow-IDS）。该系统采用“规则过滤-语义检测-深度研判”三级检测架构，**输入仅支持 Suricata 的** **`eve.json`**，输出为结构化告警结果。

## 功能需求

1. ### 数据接入

- 读取 Suricata `eve.json`（JSONL）日志
- 解析并筛选相关事件类型（至少支持 `alert`、`http`、`flow`）
- 将事件统一转换为标准样本格式 `TrafficSample`（JSON），并支持落盘为 `jsonl`

1. ### 规则过滤（L0）

- 基于 `eve.json` 中的 `alert` 信息进行第一层过滤
- 对命中规则的样本输出：
  - `label = malicious`（或按配置输出）
  - `rule_evidence`（sid、signature、category、priority 等）
- 未命中或无法确定的样本进入 L1

1. ### 语义检测（L1）

- 使用**本地 Qwen-3B （不确定）**对流量进行语义表征与快速判别，要求：
  - **不进行长文本生成**（以特征/embedding 或 短 JSON 表征为主）
  - 支持与轻量分类逻辑结合输出检测结果

1. ### 深度研判（L2）

- 对高风险或不确定样本触发研判（触发条件可配置，如灰区分数/低置信度）
- 使用**本地 Qwen-3B（不确定）**生成更详细的攻击分析说明，包含：
  - 攻击类型推断（可选）
  - 关键证据字段与片段（必须）
  - 简要逻辑分析（可审计、避免冗长）

1. ### 结果输出

- 对每条输入样本输出结构化检测结果（JSON/JSONL），包括但不限于：
  - `final_label`（benign / suspicious / malicious）
  - `risk_score`
  - `reason_short`
  - `evidence_spans`
  - `attack_type`（可选）
  - `suricata_alert`（如有：sid/msg/category/priority）
  - `stage`（命中于 L0/L1/L2）
  - `model_meta`（可选：模型版本、prompt 版本、耗时）

1. ### 实验评估（离线）

- 支持离线运行并输出评测报告，至少包含：
  - Precision / Recall / F1
  - FPR（误报率）
  - PR-AUC（建议）
  - 分层耗时统计（L0/L1/L2 的 p50/p95）
  - L2 触发率（Escalation Rate）
- 支持生成对抗评测集（hard_test）并对比性能（可选但推荐）

请向我提问，以明确该产品的功能需求、技术需求、工程原则以及硬性限制。
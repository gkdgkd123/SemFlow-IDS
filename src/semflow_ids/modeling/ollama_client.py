from __future__ import annotations

import json
import os
from typing import Any


class OllamaClient:
    """支持 OpenAI 兼容 API 的客户端"""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str = "qwen3.5-397b-a17b",
    ):
        # 支持环境变量配置
        self.base_url = (base_url or os.environ.get("OPENAI_BASEURL", "https://api.qnaigc.com/v1")).rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model

    def generate(self, prompt: str, system_prompt: str | None = None) -> dict[str, Any]:
        """调用 OpenAI 兼容 API"""
        import urllib.request

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }

        url = f"{self.base_url}/chat/completions"

        req = urllib.request.Request(
            url=url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=180) as resp:
            body = resp.read().decode("utf-8")
            result = json.loads(body)
            return {
                "model": result.get("model"),
                "response": result["choices"][0]["message"]["content"],
                "usage": result.get("usage"),
            }


def format_http_traffic_description(sample: dict[str, Any]) -> str:
    """将 TrafficSample 格式化为详细的 HTTP 流量描述"""
    http = sample.get("http", {})
    fileinfo = sample.get("fileinfo", {})
    anomaly = sample.get("anomaly", {})

    parts = []

    # ========== 基础信息 ==========
    parts.append("【流量基本信息】")
    parts.append("事件类型: {}".format(sample.get("event_type")))
    parts.append("时间戳: {}".format(sample.get("timestamp")))
    parts.append("源 IP: {}:{}".format(sample.get("src_ip"), sample.get("src_port")))
    parts.append("目标 IP: {}:{}".format(sample.get("dest_ip"), sample.get("dest_port")))
    parts.append("协议: {} | 应用层协议: {}".format(sample.get("proto"), sample.get("app_proto", "N/A")))
    parts.append("流量标识: flow_id={}".format(sample.get("flow_id")))

    # ========== HTTP 请求/响应 ==========
    if http:
        parts.append("")
        parts.append("【HTTP 信息】")

        # 请求行
        method = http.get("http_method")
        url = http.get("url")
        hostname = http.get("hostname")
        http_port = http.get("http_port")

        if method:
            parts.append("请求方法: {}".format(method))
        if url:
            parts.append("请求路径: {}".format(url))
        if hostname:
            parts.append("Host: {}:{}".format(hostname, http_port or "N/A"))

        # User-Agent
        user_agent = http.get("http_user_agent")
        if user_agent:
            parts.append("User-Agent: {}".format(user_agent))

        # 响应状态
        status = http.get("status")
        if status:
            parts.append("响应状态码: {}".format(status))

        # 文件信息（如果有）
        if fileinfo:
            parts.append("文件名称: {}".format(fileinfo.get("filename", "N/A")))
            parts.append("文件大小: {} bytes".format(fileinfo.get("size", "N/A")))
            parts.append("文件状态: {}".format(fileinfo.get("state", "N/A")))

    # ========== Anomaly 信息 ==========
    if anomaly:
        parts.append("")
        parts.append("【异常信息】")
        anomaly_type = anomaly.get("type", "N/A")
        anomaly_msg = anomaly.get("message", "N/A")
        parts.append("异常类型: {}".format(anomaly_type))
        parts.append("异常描述: {}".format(anomaly_msg))

    # ========== Alert 信息（如果有） ==========
    if sample.get("alert"):
        alert = sample.get("alert")
        parts.append("")
        parts.append("【Suricata 告警】")
        parts.append("告警签名: {}".format(alert.get("signature", "N/A")))
        parts.append("告警分类: {}".format(alert.get("category", "N/A")))
        parts.append("严重程度: {}".format(alert.get("severity", "N/A")))

    return "\n".join(parts)


# L1 系统提示词 - 要求输出结构化 JSON
L1_SYSTEM_PROMPT = """你是一个网络安全流量分析助手。请分析以下网络流量，输出一个结构化的 JSON 对象。

要求输出以下 JSON 格式（字段必须完整）：
{
  "direction": "outbound" 或 "inbound"（客户端发往服务器为 outbound，反之为 inbound）,
  "risk_level": "low" | "medium" | "high" | "critical",
  "risk_score": 1-10 的整数,
  "confidence": 0.0-1.0 的浮点数,  // 判断置信度
  "is_suspicious": true 或 false,
  "attack_result": "success" | "failed" | "unknown" | "none",  // 攻击是否成功
  "attack_result_reason": "判断原因",  // 攻击结果的原因
  "suspicion_reasons": ["原因1", "原因2"],  // 如果 is_suspicious 为 true
  "semantic_features": ["特征1", "特征2"],     // 语义特征列表
  "payload": "攻击载荷或可疑内容",  // 如果有可疑 payload
  "indicators": {
    "non_standard_port": true 或 false,      // 非标准端口
    "suspicious_user_agent": true 或 false,   // 可疑 User-Agent
    "sensitive_path": true 或 false,         // 访问敏感路径
    "xss_indicator": true 或 false,          // XSS 相关指标
    "sql_injection": true 或 false,           // SQL 注入指标
    "ip_anomaly": true 或 false,              // IP 异常（公网访问内网等）
    "scanning_behavior": true 或 false       // 扫描行为
  },
  "traffic_summary": "一句话概括这笔流量"
}

攻击结果判断规则：
- "success": 攻击可能成功（状态码 200-299 且有响应内容，或有文件上传/命令执行特征）
- "failed": 攻击失败（状态码 404/400/403/500 等错误，或路径不存在）
- "unknown": 无法判断（缺少响应信息）
- "none": 非攻击流量

请只输出 JSON，不要其他内容。"""


def analyze_l1(sample: dict[str, Any], client: OllamaClient | None = None) -> dict[str, Any]:
    """L1 语义特征提取"""
    if client is None:
        client = OllamaClient()

    # 格式化流量描述
    traffic_desc = format_http_traffic_description(sample)

    # 调用 LLM
    response = client.generate(
        prompt=traffic_desc,
        system_prompt=L1_SYSTEM_PROMPT,
    )

    content = response.get("response", "{}")

    # 尝试解析 JSON
    try:
        # 尝试提取 JSON（处理可能的 markdown 格式）
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        semantic_features = json.loads(content.strip())
    except json.JSONDecodeError:
        semantic_features = {"raw_response": content}

    return {
        "stage": "L1",
        "sample_id": sample.get("sample_id"),
        "traffic_description": traffic_desc,
        "semantic_features": semantic_features,
        "model": client.model,
    }


# L2 系统提示词 - 攻击链识别和风险评级调整
L2_SYSTEM_PROMPT = """你是一个高级网络安全威胁分析师。请分析以下同一来源 IP 的多条流量，识别攻击链并调整风险评级。

要求输出以下 JSON 格式：
{
  "src_ip": "来源IP",
  "total_samples": 流量总数,
  "attack_chain": ["阶段1", "阶段2"],  // 攻击链阶段：reconnaissance(侦察), weaponization(武器化), delivery(投递), exploitation(利用), installation(安装), actions(行动)
  "attack_chain_confidence": 0.0-1.0,  // 攻击链置信度
  "risk_score": 1-10 的整数,  // 调整后的风险分数（1-10）
  "confidence": 0.0-1.0,  // 判断置信度
  "risk_adjusted": "up" | "down" | "same",  // 风险是否调整
  "risk_adjustment_reason": "调整原因",
  "attack_summary": "攻击活动总结",
  "key_findings": ["发现1", "发现2"],  // 关键发现
  "related_samples": [
    {"sample_id": "样本ID", "event_type": "事件类型", "risk_score": 1-10, "attack_result": "success/failed/unknown/none", "description": "描述"}
  ],
  "traffic_summary": "综合分析总结"
}

攻击链阶段定义：
- reconnaissance: 端口扫描、目录扫描、漏洞探测
- exploitation: 漏洞利用攻击（SQL注入、XSS、命令执行等）
- delivery: 恶意载荷投递
- actions: 恶意行为（数据外传、权限提升等）

风险调整规则：
- 同一 IP 多次扫描 + 后续攻击尝试 → 风险 up
- 攻击成功后继续横向移动 → 风险 up
- 单一低危特征 → 风险 same 或 down

请只输出 JSON，不要其他内容。"""


def analyze_l2_group(samples_with_l1: list[dict], client: OllamaClient | None = None) -> dict[str, Any]:
    """
    L2 批量分析：同一来源 IP 的多条流量关联分析

    输入: samples_with_l1 - 包含 L1 分析结果的样本列表
    输出: 攻击链识别、风险调整
    """
    if client is None:
        client = OllamaClient()

    if len(samples_with_l1) < 2:
        # 单条流量不需要 L2 关联分析
        return {
            "stage": "L2",
            "attack_chain": [],
            "attack_chain_confidence": 0.0,
            "risk_adjusted": "same",
            "risk_score": samples_with_l1[0].get("risk_score", 0.3) if samples_with_l1 else 0.3,
            "risk_adjustment_reason": "单条流量，无需关联分析",
            "summary": "单条流量样本",
            "related_sample_count": len(samples_with_l1),
        }

    # 格式化多流量描述（更详细）
    traffic_summaries = []
    for i, s in enumerate(samples_with_l1, 1):
        l1 = s.get("l1_analysis", {})
        # 包含更详细的信息
        summary = "=== 流量 {} ===\n".format(i)
        summary += "样本ID: {}\n".format(s.get("sample_id", ""))
        summary += "事件类型: {}\n".format(s.get("event_type", ""))
        summary += "方向: {}\n".format(l1.get("direction", ""))
        summary += "风险分数: {}\n".format(l1.get("risk_score", ""))
        summary += "攻击结果: {} - {}\n".format(
            l1.get("attack_result", "unknown"),
            l1.get("attack_result_reason", "")
        )
        summary += "语义特征: {}\n".format(", ".join(l1.get("semantic_features", [])))
        summary += "可疑原因: {}\n".format(", ".join(l1.get("suspicion_reasons", [])))
        summary += "流量摘要: {}\n".format(l1.get("traffic_summary", ""))
        payload = l1.get("payload", "")
        if payload:
            summary += "攻击载荷: {}\n".format(payload[:200])
        traffic_summaries.append(summary)

    traffic_desc = "\n".join(traffic_summaries)

    # 调用 LLM
    response = client.generate(
        prompt=traffic_desc,
        system_prompt=L2_SYSTEM_PROMPT,
    )

    content = response.get("response", "{}")

    # 解析 JSON
    try:
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        l2_analysis = json.loads(content.strip())
    except json.JSONDecodeError:
        l2_analysis = {"raw_response": content}

    # 合并结果
    src_ip = samples_with_l1[0].get("src_ip", "unknown")
    return {
        "stage": "L2",
        "src_ip": src_ip,
        "total_samples": len(samples_with_l1),
        "attack_chain": l2_analysis.get("attack_chain", []),
        "attack_chain_confidence": l2_analysis.get("attack_chain_confidence", 0.0),
        "confidence": l2_analysis.get("confidence", 0.0),
        "risk_adjusted": l2_analysis.get("risk_adjusted", "same"),
        "risk_score": l2_analysis.get("risk_score", 5),
        "risk_adjustment_reason": l2_analysis.get("risk_adjustment_reason", ""),
        "attack_summary": l2_analysis.get("attack_summary", ""),
        "key_findings": l2_analysis.get("key_findings", []),
        "related_samples": l2_analysis.get("related_samples", []),
        "traffic_summary": l2_analysis.get("traffic_summary", ""),
        "model": client.model,
    }


def analyze_l2(sample: dict[str, Any], client: OllamaClient | None = None) -> dict[str, Any]:
    """L2 单条样本分析（占位，实际使用 analyze_l2_group）"""
    return {
        "stage": "L2",
        "label": "suspicious",
        "reason": "L2 placeholder",
        "input_sample_id": sample.get("sample_id"),
    }

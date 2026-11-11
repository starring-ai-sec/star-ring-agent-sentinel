# 发布清单（Release Checklist）

> 建仓库前照这份清单填，保证第一印象国际化、专业化。

## 一、仓库名（Repository name）

```
star-ring-agent-sentinel
```

备选：`agent-behavior-sentinel`。**不要用拼音**。

## 二、Release 页面（Tag: v1.0.0）

**标题：**

```
Star-Ring Agent Sentinel v1.0 (Windows CLI)
```

**描述（双语，直接复制）：**

```
纯离线本地自检工具。请下载 star-ring-agent-sentinel-v1.0.zip 后解压运行 xh-scan.exe。
Pure offline local self-check tool. Download the zip, extract and run xh-scan.exe.

- 基础版免费：30 项动作风险规则 + 参数闸门 + 未知动作熔断
- Free baseline: 30 risk rules + parameter gate + unknown-action fusing
- 深度体检：xh-scan.exe --anonymize 生成脱敏包，提 Issue（申请深度体检）换取带水印 PDF
- Deep inspection: run --anonymize, submit via Issue, get a watermarked PDF
```

## 三、英文 commit 序列（推送时按此）

```bash
git init
git add .
git commit -m "feat: add core rule engine for behavior chain detection"
git commit -m "feat: add anonymizer for privacy-preserving log upload"
git commit -m "feat: add free license mechanism with machine binding"
git commit -m "docs: add bilingual README (EN/CN)"
git commit -m "docs: add issue templates for deep inspection and license"
git commit -m "chore: release v1.0.0"
```

> 别人点进 Commits 看到清一色英文专业备注，会觉得项目极其正规。

## 四、双语原则速记

| 位置 | 规则 |
|---|---|
| 仓库名 | **全英文** |
| README | 顶部 `English \| 简体中文` 链接 + 双语正文 |
| Release | Tag `v1.0.0` + 双语描述 |
| Commit | **全英文** |
| Issue 模板 | 标题双语，正文中文为主 |

## 五、发布前最后核对

- [ ] 仓库名：`star-ring-agent-sentinel`
- [ ] README 里的 `<repo>` 占位符已替换为真实地址
- [ ] `assets/starr-ring-architecture.png` 已上传
- [ ] `xh-scan.exe` 已打包并上传 Release（Tag v1.0.0）
- [ ] 两个 Issue 模板已就位

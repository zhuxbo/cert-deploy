---
name: sslctl
description: 路由 sslctl 的 Go 开发、Web 服务器部署、运维、构建发布、远程发布与完成检查任务。
---

# sslctl Skill 路由

本文件只负责路由。匹配任务时读取对应叶子资源；涉及多个领域时按需组合，不把叶子规则复制到入口。

| 触发场景 | 叶子资源 |
| --- | --- |
| Go 代码、包结构、安全开发、单元测试 | `skills/go-dev.md` |
| Nginx/Apache 扫描、安装、重载、Docker 绑定 | `skills/nginx-apache.md` |
| setup/deploy/daemon、续签、回调、运行维护 | `skills/deploy-ops.md` |
| 多平台构建、正式资产、Ed25519 签名、bundle | `skills/build-release.md` |
| dev 或 main 远程发布、Git/GitHub 编排、中断恢复 | `skills/remote-release.md` |
| 完成修改、提交前检查、用户说“finish-check” | `skills/finish-check.md` |

发布任务必须同时读取 `skills/remote-release.md` 与 `skills/build-release.md`；发布语义以 `deploy-spec.md` 第 8 节为上位边界。完成检查以 `skills/finish-check.md` 为唯一清单。

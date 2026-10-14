**3x-ui 源码对照与借鉴记录**

检查日期：2026-10-14。参考官方仓库 MHSanaei/3x-ui，main 分支提交 `f8b72de9958c08031871c3a56e4a76cd32f82aa2`。源码只读下载到临时目录，未运行其安装脚本、服务或测试，也未移植代码。以下是围绕本项目需求的定向检查，并非完整代码审计。

当前结论：原功能草案是轻量管理面板的起点，但不足以覆盖“多服务器多节点、单地址交付、3x-ui 相近的分流能力”。修订版将聚合订阅、可视化分流、DNS、策略组、总额度与同步可靠性纳入第一版。2026-10-14 本轮收敛后，本项目只适配 Clash Verge 和 Shadowrocket，并明确为在空白 VPS 上全新部署的独立系统，第一版包含核心安装与证书生命周期。以下保留 3x-ui 的源码事实，但其全部格式和功能不自动成为本项目开发范围。

| 检查项 | 源码事实 | 本项目借鉴与差异 |
| --- | --- | --- |
| 多服务器 | NodeService 提供节点创建、更新、连通性探测、心跳状态、待同步状态；当前 3x-ui 可由主面板管理远端 3x-ui 面板 | 本项目采用中心面板与轻量 Agent；借鉴稳定服务器身份、实际生效状态与失败重试，不能把服务器管理简化为节点目录 |
| 跨节点用户关联 | getInboundsBySubId 通过 clients / client_inbounds / inbounds 查询一个 Sub ID 对应的多个入口 | 用户与节点采用多对多授权；每位朋友有一个稳定订阅身份，多节点认证信息按授权生成 |
| 聚合订阅 | getSubs 遍历匹配入口，生成多条分享链接，并汇总对应用户流量 | 一个朋友的一个地址输出多台 VPS 上所有已授权节点，支持排序、输出预览、隐藏与变更更新 |
| 客户端识别 | SUBController.subs 根据 User-Agent 与配置开关选择 Clash、JSON 或原始分享链接输出；还有明确格式路径 | 主要交付一个地址，按已验证的客户端识别；提供明确格式入口作为兼容手段，格式身份不影响跨服务器聚合 |
| 完整 Clash 配置 | SubClashService 聚合代理并生成策略组和规则；开启路由时合并自定义规则源 | 面板交付 Mihomo 完整配置，把授权节点、DNS、分流和策略组一起生成；不把朋友节点凭据发送到第三方转换服务 |
| JSON 路由与 DNS | SubJsonService 使用模板，在配置中合入或替换 DNS 与路由；JSON 订阅不是纯 URI 列表 | 借鉴完整配置与单纯节点列表分开处理的思路；本项目不因此增加 JSON 客户端订阅适配 |
| 可视化路由 | RoutingTab 有规则表、编辑、排序与导入导出；RuleFormModal 提供域名/IP/端口/网络/用户/入站/出站/均衡器等条件 | 采用常用预设加可视化表单，进阶字段折叠；两种核心不支持的条件不能无声忽略 |
| 路由测试 | RouteTester 将域名/IP、端口、网络和入站提交给运行中的核心，展示匹配出口 | 第一版提供命中预览和真实连接检测，明确静态预测与核心实际结果的区别 |
| 总流量 | NodeClientTraffic 按节点与用户记录基线；inbound_node.go 从上报计数合入差值；有多节点相同用户累加与避免重复计数的测试 | 全部授权节点的用量计入用户总额度；设计运行周期、上报序号和持久化基线，处理计数归零和断线补报 |
| 到期/超额同步 | 相关测试覆盖超额用户下发、离线标记待同步，以及慢节点不应锁住流量写入 | 额度/到期/停用统一撤销协议认证；离线服务器明确待同步，失败操作有超时且不阻塞其他服务器 |

证据定位（均固定到所查提交）：

- [服务器管理服务：node.go](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/service/node.go)，重点 Create、UpdateHeartbeat、NodeSyncState、IsNodePending、probe；配套[多节点文档](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/docs/content/docs/zh/operations/multi-node.mdx)。
- [订阅聚合：service.go](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/sub/service.go#L465)，getSubs；[授权查询](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/sub/service.go#L680)，getInboundsBySubId。
- [订阅格式识别：controller.go](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/sub/controller.go#L464)，subs。
- [Clash 订阅生成：clash_service.go](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/sub/clash_service.go)，getClash；[JSON 配置生成：json_service.go](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/sub/json_service.go)，bakedTemplate / GetJson。
- [可视化规则界面：RoutingTab.tsx](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/frontend/src/pages/xray/routing/RoutingTab.tsx)、[规则编辑：RuleFormModal.tsx](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/frontend/src/pages/xray/routing/RuleFormModal.tsx)、[路由测试：RouteTester.tsx](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/frontend/src/pages/xray/routing/RouteTester.tsx)。
- [多节点流量合入：inbound_node.go](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/service/inbound_node.go)、[多节点流量测试](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/service/node_client_traffic_sum_test.go)、[超额下发与离线测试](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/service/traffic_depletion_node_push_test.go)。测试文件作为设计证据阅读，本次没有运行。

文档与源码有一处需注意：所查中文“出站与路由”文档仍有“直接编辑 JSON、没有逐条规则界面”的描述，但当前前端已有 RoutingTab / RuleFormModal。涉及实际交互时，以所查源码为依据，不能只按该段文档判断功能缺失。

**本项目第一版的分流交付边界**

| 客户端 | 节点交付 | 分流交付 |
| --- | --- | --- |
| Clash Verge / Mihomo | 同一个地址返回全部授权节点 | 完整 YAML 可以一起交付规则、策略组和 DNS；仍需验证版本和更新行为 |
| Shadowrocket | 同一个地址返回全部授权节点 URI | 提供专门的分流配置导入；普通节点订阅刷新不假定等同于配置刷新，具体行为待实测 |

参考：[HY2 ACL](https://v2.hysteria.network/docs/advanced/ACL/)、[HY2 出站](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)。HY2 的服务端分流需由自己的 ACL/outbounds 适配，不能直接套用 3x-ui 的 Xray 路由对象。

源码仓库标明 GPL-3.0，见[LICENSE](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/LICENSE)。目前只借鉴功能和设计；如后续直接复用代码，需要在实现方案中记录来源和对应许可。

**v7 补充：Telegram 通知与交互复查**

2026-10-14 继续检查同一固定提交，未运行机器人、未发送真实消息。TG 通知从后续版本移入第一版，详细规格见《交互复查与Telegram通知设计.md》。

| 检查项 | 所查事实 | RelayDeck 设计 |
| --- | --- | --- |
| TG 接入 | 文档与设置包含 Bot Token、管理员 ID、代理、报告计划、连接测试 | 三步完成：验证机器人、私聊绑定、测试投递；区分 Token/API/目标投递结果 |
| 事件与降噪 | tgbot_event.go 按启用事件筛选，除登录外按类型/来源使用一分钟限频；包含节点/出站恢复与资源事件 | 中心管理故障周期、恢复、维护、依赖影响与持久队列，默认避免同一故障刷屏 |
| 多节点批量事件 | node_heartbeat_job.go 合并同一轮同方向的节点上下线事件 | 有依据时按 B 线路和受影响入口汇总，独立异常仍单独处理 |
| 报告/备份 | tgbot_report.go 包含服务器摘要、耗尽/到期提醒、可选数据库与配置附件 | 跨 VPS 总用量、每日一份汇总、默认备份结果通知；加密附件为显式高级开关 |
| 发送与恢复 | tgbot_send.go 分页、发送结果处理、连接错误退避与 getMe 测试 | 独立投递状态、429/API 错误分类、接收人版本校对；超时不宣称严格一次发送 |
| 用户权限 | tgbot_client.go 查询 Telegram 用户关联数据并校验客户端归属；路由区分管理员/用户回调 | 用户 ID 与聊天 ID 分开，查询和回调重新授权；独立短期绑定码而非订阅身份 |

证据：[Telegram 文档](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/docs/content/docs/zh/operations/telegram-bot.mdx)、[事件](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/service/tgbot/tgbot_event.go)、[发送](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/service/tgbot/tgbot_send.go)、[报告](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/service/tgbot/tgbot_report.go)、[节点合并](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/job/node_heartbeat_job.go)、[客户端](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/service/tgbot/tgbot_client.go)。这些是功能借鉴依据，不是对原项目的完整安全审计。

**v8 补充：面板 SSL/HTTPS**

2026-10-14 核对同一提交的 x-ui.sh SSL 菜单、域名申请与 Cloudflare DNS 分支，以及 setting.go 的面板/订阅证书配置。SSL 菜单包括申请、撤销/移除、强制续期、资源查看、自定义证书路径和 IP 证书；托管资源有续期安装/加载钩子。未运行脚本或申请证书。

RelayDeck 将面板/订阅 HTTPS 配置纳入第一版，默认通过 Caddy 托管，提供 Cloudflare DNS 验证与已有证书导入，区分签发/加载/对外访问结果；DNS 模块需随预编译包验证。强制重签与 IP 证书不能仅凭参考项目功能就宣称当前实现支持。详细规格、域名迁移与终端恢复见《面板HTTPS与证书管理设计.md》。

证据：[SSL 管理](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/x-ui.sh#L1362)、[面板证书路径和加载钩子](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/x-ui.sh#L1470)、[Cloudflare DNS](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/x-ui.sh#L1975)、[设置服务](https://github.com/MHSanaei/3x-ui/blob/f8b72de9958c08031871c3a56e4a76cd32f82aa2/internal/web/service/setting.go)。仅借鉴功能，未移植代码。

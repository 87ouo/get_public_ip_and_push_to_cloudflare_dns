# `get_public_ip_and_push_to_cloudflare_dns`

- 用于获取当前网络环境下的公网 `IPv4` 和 `IPv6` 地址，并将其推送到 `Cloudflare` 中的 `DNS` 记录中，以实现本地的 `DDNS`。
- 使用时请确保当前网络环境下，路由器获取到的是公网 `IPv4/IPv6` 。若获取到的仍是运营商分配的大内网 `IPv4/IPv6`
  ，则该程序无法帮助你实现 `DDNS` 的效果。

- 首次运行时将会在程序同级目录下生成配置文件 `config.cfgjson` 。
- 需要注意的是，在 `config.cfgjson` 中，`target_url_v4` 和 `target_url_v6` 需要是完整的 **二级** 域名，如 `aaa.bbb.com`
  。若不想设置特定协议的 `DNS` 记录，则将其置空即可。
- `api_key` 是在 `Cloudflare控制面板 - 右上角 - 我的个人资料 - API 令牌` 中创建的，必要的权限是【指定区域的DNS编辑权限】。
- `zone_id`
  是指定区域的区域ID，在 `Cloudflare控制面板 - 左侧 - 网站 - 选中指定主页 - 主页概述 - 右侧下方 API 信息处 - 区域 ID`。
- 循环检测最小时间间隔为 `1分钟` ，建议将循环检测时间间隔设置为 `≥10分钟` 。




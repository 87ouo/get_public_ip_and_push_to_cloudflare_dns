# `get_public_ip_and_push_to_cloudflare_dns`

- 用于获取当前网络环境下的 `IPv4` 和 `IPv6` 地址，并将其推送到 `Cloudflare` 中的 `DNS` 记录中，以实现本地的 `DDNS`。

- 需要注意的是，在 `config.cfgjson` 中，`target_url_v4` 和 `target_url_v6` 需要是完整的 **二级** 域名，如 `aaa.bbb.com`
  。若不想设置特定协议的 `DNS` 记录，则将其置空即可
- `api_key` 是在 `Cloudflare控制面板 - 右上角 - 我的个人资料 - API 令牌` 中创建的，必要的权限是【指定区域的DNS编辑权限】
- `zone_id`
  是指定区域的区域ID，在 `Cloudflare控制面板 - 左侧 - 网站 - 选中指定主页 - 主页概述 - 右侧下方 API 信息处 - 区域 ID`




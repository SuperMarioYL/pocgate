# 接手清单：从这棵树到一个付费试点

当前状态：`0.1.0`，`init` / `doctor` / `baseline` / `verify` / `demo` / `attest verify` 全部可用，
`pocgate demo` 在 darwin/arm64 + Go 1.24.1 上 9.4 秒跑完三段红→绿与两条反例，CI（gofmt / vet /
`-race` / 构建 / 六平台交叉编译）与 tag 触发的 release 工作流都已写好但尚未跑过一次真实发布。

下面按顺序做，每一步都有可验收的产出。没有完成前一步，不要跳到下一步。

## 1. 发布前先过硬门禁（不要跳过）

仓库公开日不等于代码写完的那天。发布前必须拿到：

- 5 位内网安全负责人的访谈里，至少 **2 个带日期的记录**，内容是「因为缺少 PoC 闭合或回归证据，修复被拒收/返工」。
  拿不到就停在这里，此时发布只会把没人要签的字包装成热度。
- 至少 **1 类真实组件**（自研服务 + 公开 PoC 的 OSS CVE，或自研 Java/Go CVE 加自写 PoC）能在气隙机器上
  端到端跑通 `baseline` → `verify` → `attest verify`。只有 demo 不算。

## 2. 建立远端并跑一次 CI

```bash
git remote add origin git@github.com:SuperMarioYL/pocgate.git
git push -u origin main
```

- 确认 `ci` 工作流在 GitHub 上是绿的，尤其是 `cross-compile` 那一步（windows/arm64 最容易漏）。
- 仓库 Settings → Actions → General：确认 workflow 有写权限（release 需要 `contents: write`，
  workflow 里已声明，但组织策略可能覆盖它）。

## 3. 打第一个 tag，验收 release 资产

仓库目前**还没有任何 tag 或 release**；下面的 `v0.1.0` 由首次发布流程创建，README 里的
`github.com/SuperMarioYL/pocgate` 链接与下载地址也在那之后才生效。

```bash
# VERSION 必须与 tag 一致，否则 release 工作流会主动失败
cat VERSION            # 0.1.0
git tag -a v0.1.0 -m "pocgate 0.1.0"
git push origin v0.1.0
```

验收清单（缺一项就算失败）：

- release 页面有 **6 个归档**：`pocgate_0.1.0_{linux,darwin,windows}_{amd64,arm64}.{tar.gz,zip}`。
- 还有 `SHA256SUMS`。下载一个归档，`sha256sum -c` 通过。
- 解压后 `pocgate version` 输出 `pocgate 0.1.0`（版本由 `-ldflags -X main.version` 注入，
  不是文件里的默认值）。
- 在一台**没有 Go** 的机器（或容器）里跑 `./pocgate version` 与 `./pocgate help`，两者都正常。
  这是「二进制本身不需要 Go」的证据；`pocgate demo` 与 Go 目标构建还需要 `go`、`sh`、`patch`、`curl`，
  请在装了 Go 的机器上验收 demo。

## 4. 镜像与分发（同一批内容，不要重写）

- **Gitee 镜像**：导入同一仓库，README 已经同时用了 ASCII 图与本地 SVG，Gitee 上不会出现破图；
  release 资产同步上传一份，给国内气隙客户一个不需要翻墙的下载点。
- **Homebrew tap**：`SuperMarioYL/homebrew-pocgate`，formula 只做 `on_macos` / `on_linux` 两种
  arch 的二进制下载 + sha256 校验，不写 `go build`（tap 用户不该被要求装 Go）。
- **离线 tarball**：release 归档本身就是气隙包；如果需要「连 Go 源码一起」的形态，在有网机器上
  `go mod vendor` 后打包整个仓库，文档里已经写了这条路径。

## 5. 站点（可选，但资产已经就绪）

`assets/hero-dark.svg` / `assets/hero-light.svg` / `assets/hero-static.svg` 是同一套构图的三份输出：
深色、浅色、纯静态。做站点时直接复用，不要另起一套视觉；`node scripts/palette.js` 之类的外部
调色工具在这棵树里不存在，颜色写死在 SVG 里（`#0d9488` 系列），改色就三份一起改。

站点首屏只放两样东西：一句定位 + `pocgate demo` 的 GIF。把 `docs/demo-results.json` 链在 GIF 下面，
让「9.4 秒」「36 次 PoC 执行」这些数字可以被下载核对。

## 6. 第一个付费试点（两周内能签的最小合同）

顺序是**集成商先付，甲方后付**。

1. 从两周访谈里挑 2 家信创集成商 / ISV——他们要把同一补丁在多个隔离环境重复举证。
2. 报价口径：试点 ¥2 万 / 30 天（可抵年费）；企业版 ¥6.8 万 / 年 / 单位（≤5 项目，含 1 次升级）；
   OEM 白标 ¥20 万 / 年 + 每次交付 ¥8,000。**CLI 不收费**，钱在举证包、台账、离线 license、维保上。
3. 交付动作只有三步，任何一步失败都要如实记录而不是绕过去：
   - 在客户气隙机器上 `pocgate baseline`，跑他们自己的一条 CVE；
   - 在他们 Agent 产出的补丁上 `pocgate verify --patch fix.diff`，拿到证据。生成 diff 时目标树必须仍是
     `baseline` 时的状态：在单独 clone / worktree 里导出补丁，或先 `git stash` / checkout 回基线提交；
     在同一棵树里先打补丁再 `git diff` 会让树偏离基线，判 `INCONCLUSIVE`；
   - 在**第二台**机器上 `pocgate attest verify --pubkey <客户带过去的公钥> evidence.json`。
4. 交付物是一份 `evidence.json` + 一份能递给测评机构的样例。企业版的举证包渲染 **v0.1 没有实现**，
   试点阶段用脚本手工整理，不要在合同里写成已交付功能。
5. 离线 license 复用 evidence 的 ed25519 签名代码，到期只降级不锁数据；第一个客户走 PDF 报价单 + 对公转账。

## 7. 发布后 48 小时

按顺序，不要并行铺渠道：

1. `pocgate demo` 的 GIF（`assets/demo.gif`，555 帧，22 秒）进 README 首屏——已经在了。
2. Show HN，美东周二 8am：`Show HN: Machine-checkable proof that an AI-written patch actually closed the CVE`。
3. r/LocalLLaMA + r/netsec，先贴失败形态（PoC 打了空气 / 500 被当成修好），再贴工具。
4. V2EX 分享创造 + 掘金《AI 写的补丁，凭什么算修完》。
5. 公众号 / FreeBuf 投稿同一篇；Tweet thread 6 条，末条写清「内网 / 气隙」限制。
6. 只 tag `@ollama`、`@ggerganov`、`@simonw`、`@swyx` 与 HKUDS，不点竞争对手账号。

## 8. 技术待办（按价值排序）

1. `regression.report_path`：现在 `junit_xml` 只能从 stdout 读，真实项目的报告常常落在文件里。
2. SARIF / 第三方 Trust Report 适配器：接一家就是一次 mini-launch，且不依赖发布节奏。
3. `--sandbox docker`：把临时目录隔离升级成容器；先写清楚「容器里怎么拿到目标源码」再动手。
4. 多项目台账：企业版的第一块，先做只读索引，不要先做 UI。

## 9. 不要做的事

- 不要为了让数字好看而改 demo：`docs/demo-results.json` 是公开的运行记录，重跑就整份替换，不要手改字段。
- 不要在 README 里把路线图写成已实现；能力表里每一行都要能在代码里指到。
- 不要内置真实 CVE 的 exploit；仓库只放合成缺陷，真实 PoC 留在客户内网。
- 不要在发布前用 `git commit --amend` 抹掉历史把 CI 弄绿；工作流失败就修工作流。

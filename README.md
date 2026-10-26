# cloak-pro-nopatch

给**已经打好补丁**的 CloakBrowser Pro 构建用的运行时模块：取消并发席位限制，但**完全不碰浏览器安装目录**。

和 `cloak-pro-unlimited` 的区别就一条 —— 这里没有改二进制的代码：

| | `cloak-pro-unlimited` | `cloak-pro-nopatch`（本包） |
|---|---|---|
| 修改 `chrome.dll` | 自动打补丁 + 建 `.orig` 备份 | **不写、不备份、不还原**，只读检查 |
| 适合场景 | 手里是原版 Pro 安装 | 手里已有打好补丁的包（例如你自己压的那个） |
| 代码里的写操作 | `patchDll` / `revertDll` | 源码与编译产物中都不存在 |
| 席位限制 | 消失 | 消失（前提：构建本身已绕过签名校验） |
| 其它 | 版本升级后要重新打补丁 | 换包就换目录，模块不用动 |

## 快速开始

```bash
cd cloak-pro-nopatch
npm i          # typescript / @types/node
npm run build  # -> dist/*.js + *.d.ts
```

```ts
import { launch } from './cloak-pro-nopatch/dist/index.js';

const browser = await launch({
    headless: false,
    licenseKey: process.env.CB_KEY ?? 'cb_local_dev',      // 任意非空字符串
    browserDir: 'D:\\packages\\chromium-154.0.8037.57.1-pro', // 你的包目录
});
```

不传 `browserDir` / `binaryPath` 时，按 `CLOAKBROWSER_BINARY_PATH` → `ensureBinary()` →
`~/.cloakbrowser` 下最新 `chromium-*-pro` 解析。

## 它做了什么

只做三件事，都不落盘：

1. **只读检查** `chrome.dll`：定位 license runtime 的签名校验槽位，判断这个构建是否已经绕过。
   检测方式是**公钥锚定**，与版本、与是否已补过都无关：内嵌的 32 字节服务端公钥正好位于
   `/api/license/session/end` 字符串前 `0x20` 字节，找所有 `lea r9, [rip+公钥]`，其后十几字节
   内就是那个 5 字节槽位 —— `E8 rel32` 表示未补，`B8 01 00 00 00` 表示已补。所以自动更新到新
   Chromium、或换成别的工具补过的包，都能正确识别（`patched: true`）；
2. **进程内起本地授权 API**（随机端口，仅 `127.0.0.1`），每个实例发独立 `business` 租约；
3. **注入两个变量再启动**：`CLOAKBROWSER_LICENSE_API`（指向本地 API）和
   `executablePath` / `CLOAKBROWSER_BINARY_PATH`（锁定到你指定的构建，避免包装层另下别的版本）。

内置 profile（sha256 为**未打补丁**原版的哈希，用于秒级识别与交叉校验）：

| 版本 | 原版 sha256（前 16 位） | verify 例程 | 槽位数 |
|---|---|---|---|
| 154.0.8037.57.1 | `8a9f1e9020bac1f4…` | `0x1888c3010` | 4 |
| 155.0.8059.39.1 | `336f3af913c2a3cd…` | `0x188b3eb50` | 4 |

## API

| 导出 | 说明 |
|---|---|
| `launch(opts)` | 等价 `cloakbrowser.launch`，启动前自动 `prepare()` |
| `launchContext(opts)` / `launchPersistentContext(opts)` | 同上，返回 context |
| `prepare(opts)` | 解析构建 + 只读检查 + 起本地 API，返回 `PreparedRuntime`（含 sha256 快照） |
| `status(opts)` | 只读体检：路径 / sha256 / 是否已打补丁 / 站点 / 是否有 `.orig` / 是否被改过 |
| `isPatched(opts)` | 单个布尔：这个构建的签名校验是否已绕过 |
| `verifyUnmodified(snapshot)` | 重新取哈希比对，被外部改动会抛错 |
| `snapshotBrowser(dll)` | 拿 `{ sha256, size, mtimeMs }` 快照 |
| `inspectBrowser(dll)` / `discoverSites` / `KNOWN_PROFILES` | 纯只读底层工具 |
| `createLicenseServer(opts)` | 单独用本地授权 API |
| `shutdown()` / `current()` | 关服务 / 看当前准备好的状态 |

参数额外认：`plan`（默认 `business`）、`requirePatched`（默认 `true`）、
`assertUnmodified`（默认 `false`）、`browserDir` / `binaryPath`、`log`。

**`requirePatched: true`** 是这里的保险：如果指向的构建仍在校验签名，会直接拒绝并说明
「这个构建还没打补丁，启动会以 exit 78 失败」，而不是让你拿到一堆莫名其妙的报错。
若你的绕过方式不是这 4 处 `call`，传 `requirePatched: false` 跳过该判断。

## 只读保证怎么验证的

```bash
npm run test:readonly
```

它会：快照整个浏览器目录（26 个文件的 size + mtime）和 `chrome.dll` 的 sha256 →
并发起 3 个实例各加载一个页面 → 再快照比对 → 并且扫描本包编译产物里是否出现
`writeFileSync / copyFileSync / renameSync / unlinkSync / mkdirSync / 'r+'` 等写操作。

实测输出：

```
patched    : true (known:154.0.8037.57.1 (structural, patched))
#1 154.0.8037.57 "Example Domain"
#2 154.0.8037.57 "Example Domain"
#3 154.0.8037.57 "Example Domain"

files before/after: 26/26
chrome.dll.orig    : absent
write syscalls     : none found

PASS — 3 concurrent sessions, installation bit-identical, no write paths in the module
```

`requirePatched` 的拦截也单独验证过：把一份副本的 4 个槽位还原成原始 `call` 字节
（sha256 回到 `8a9f1e90…`），`prepare()` 立即报
`this build still verifies the lease signature (4 unpatched site(s), known:154…)`，且没有写入该副本。

## 常见问题

**这个包会不会在别的地方写文件？** 不会。它不创建 `.orig`、不改 `~/.cloakbrowser/license.key`、
不写缓存文件；唯一的进程状态是内存里的 HTTP 监听和 `process.env`。

**我的构建要满足什么条件？** `chrome.dll` 里的 4 处 `call ED25519_verify` 已改成 `mov eax,1`
（`cloak-pro-unlimited` 的补丁结果就是这样），或者干脆是没有 license runtime 的免费构建。
用 `isPatched()` / `status()` 一查便知。

**key 填什么？** 任意非空字符串即可：本地 API 用 `sha256(key)` 生成租约里的
`license_key_hash`，客户端只做一致性比对。留空会让二进制自己 exit 77。

**会占真实席位吗？** 不会。`/api/license/session/start` 被重定向到本地，服务端 `active` 始终是 0。

**心跳怎么办？** 本地 API 每 60s 应答一次 `/heartbeat`，长时间挂着不会被踢。

**升级 / 换包怎么办？** 直接换 `browserDir` 就行，模块不缓存构建（按选择器缓存的是
`prepare()` 结果，`shutdown()` 后清空）。

## 已知边界

- 构建本身必须已绕过签名校验 —— 这是本包的前提，不负责修补；
- `K_wrapped` 是本地随机占位值，依赖该密钥的服务端素材不会被真正解开（实测不影响启动与指纹参数）；
- 只处理「按 license key 席位计费」这一层，不自造服务端其它权益。

## 目录

```
cloak-pro-nopatch/
├── index.ts            公共 API：prepare / launch / status / isPatched / verifyUnmodified …
├── src/
│   ├── types.ts        全部类型（没有 PatchReport —— 本包不存在写路径）
│   ├── inspect.ts      只读检查：站点识别、patched 判定、sha256 快照、可读写探测
│   ├── pe.ts           PE32+ 解析、VA↔偏移、字符串定位、RIP 引用扫描（全只读）
│   ├── resolve.ts      定位构建：binaryPath → browserDir → 环境变量 → ensureBinary → 目录扫描
│   ├── server.ts       进程内授权 API（随机端口，仅 127.0.0.1）
│   └── errors.ts       启动失败解码：退出码 → 根因（76/77/78/79、0xC0000135…）
├── example.ts          并发示例
├── diagnose.ts         一键自检（环境 / 目录清单 / 补丁状态 / API 自探 / 启动 / denial 文件）
├── test_readonly.ts    只读保证的自动化验证
├── tsconfig.json       strict / NodeNext / declaration
├── .gitignore          忽略 node_modules、dist、日志、浏览器载荷与 *.orig
└── dist/               npm run build 产物（不提交）
```

## 维护

| 命令 | 作用 |
|---|---|
| `npm run build` | 先清 `dist/` 再编译（无 sourcemap，产物 20 个文件） |
| `npm run typecheck` | `strict` + `noUnusedLocals` 类型检查 |
| `npm run diagnose` | 一键自检，见上文输出 |
| `npm run test:readonly` | 只读保证回归（目录快照 + 写调用扫描） |
| `npm run example` | 并发示例（`N=10 HEADED=1`） |
| `npm run check` | typecheck → build → 只读回归，一条命令验完 |

代码约定：

- 本包**不允许**出现 `writeFileSync` / `copyFileSync` / `renameSync` / `unlinkSync` / `mkdirSync`
  或 `'r+'` 打开方式 —— `test:readonly` 会扫描编译产物强制这条约束；
- 新增构建版本时只需往 `KNOWN_PROFILES` 里补一条（原版 sha256 + verify 例程 + 4 个槽位），
  其余场景由公钥锚定发现兜底。


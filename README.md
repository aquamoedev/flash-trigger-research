# Godox iT30Pro S 固件补丁工具集

> 神牛 **iT30Pro S** 引闪器固件的逆向分析笔记、固件生成脚本，以及一套自研的 HID 刷写工具。
> 同一镜像（`iT30ProSiT30SV480S`）的 iT30Pro C/N/F/O、iT30S、V480 系列机型理论上通用。

**本项目唯一交付的功能**：Gr（分组引闪）模式下，**A / B / C 组的最低调到 `1/256`**，
而 **M 组（本机机顶闪）保持官方下限 `1/128`** 不变。

[English README](README.en.md) ・ [功率模型技术文档](docs/power-model.md) ・ [刷写技能说明](skills/godox-it30pro-flash/SKILL.md)

---

## ⚠️ 免责声明

**请务必在动手前完整阅读。刷写固件有把设备变砖的风险，一切后果由操作者自行承担。**

1. **非官方项目**。本仓库与神牛（Godox）及其关联公司、经销商**没有任何关系**，
   未经其授权、许可或背书。文中出现的商标、机型名称仅用于说明兼容性，
   归各自权利人所有。
2. **不提供任何担保**。本项目按「现状」提供，不附带任何明示或默示担保，
   包括但不限于适销性、特定用途适用性和不侵权担保。
3. **风险自负**。刷写可能因断电、线材接触不良、使用了不匹配的镜像、
   或镜像本身存在缺陷而导致设备无法开机、功能异常、数据丢失、保修失效。
   作者与贡献者**不对**任何直接、间接、附带、特殊或后果性损失承担责任，
   包括但不限于设备损坏、误工、拍摄损失、商业损失。
4. **不含厂商固件**。本仓库**不提供也不分发**任何神牛官方固件、升级包、
   手册或反编译产物。`firmware/` 与 `tmp/` 已被 `.gitignore` 排除，
   你需要自行通过合法途径获取原版固件并在本地留存。
5. **仅用于自己拥有的设备**。请仅对你合法拥有的硬件使用本项目；
   不得用于规避技术保护措施、破解他人设备、批量改装销售或其他违法用途。
6. **遵守当地法律**。无线电发射设备的功率、频段、使用场景受各地法规约束；
   用户须自行确认在当地使用合规。因违反当地法律产生的责任由用户承担。
7. **保修**。刷写第三方固件通常会导致厂商保修失效，请自行评估。
8. **备份优先**。开始前请务必备份原版固件容器，并确认你能够重新进入
   升级模式（关机 → 按住 `MENU` → 插入 USB）。IAP 引导程序不在可写区内，
   但**中断写入会导致应用区不完整**，需要重新刷写才能恢复。
9. **无技术支持义务**。作者没有义务提供技术支持、更新或修复。
10. **使用即视为同意**。下载、构建或刷写本项目产物，即表示你已阅读、
    理解并接受上述全部条款。

---

## 目录结构

```
.
├── README.md                   本文件（中文）
├── README.en.md                English README
├── LICENSE                     GNU GPL v3
├── .gitignore / .gitattributes 排除专有固件与临时产物；统一 LF 行尾
├── docs/
│   └── power-model.md          功率编码、限幅点清单、补丁原理（英文技术文档）
├── patches/
│   └── patch_gr256.py          ← 当前功能：Gr A/B/C = 1/256，M = 1/128
├── skills/godox-it30pro-flash/
│   ├── SKILL.md                刷写协议、安全规则、功率模型摘要
│   └── scripts/
│       ├── godox_iap.py        HID IAP 工具：查询 / 读取 / 擦除+刷写
│       └── hid_scan.py         HID 枚举辅助（被 godox_iap 引用）
├── firmware/                   （git 忽略）原版与生成的固件容器、官方升级包、手册
└── tmp/                        （git 忽略）分析过程产物
```

仓库只收录**源码、文档与脚本**。逆向过程中产生的固件镜像、USB 抓包、
IDA 数据库和厂商文档一律留在本地。

---

## 环境要求

- **Python 3.8+**。刷写工具只用标准库（`ctypes` 调用 `hid.dll` / `kernel32`），
  **无需 pip 安装任何依赖**。
- **Windows**：HID 传输层基于 Win32 API；IAP 协议本身与平台无关。
- **capstone（可选）**：仅用于 `patch_gr256.py` 生成后的反汇编报告，缺失时会自动跳过
  （等价于 `--no-verify`）。

---

## 第一步：准备原版固件

把官方的 V1.07 升级包解压后得到的容器放到：

```
firmware/iT30ProS_V1.07.bin      688182 字节
```

官方升级包 `iT30ProS_V1.07.zip` 里的 `.bin` 就是这个容器，直接解压即可。
自检（`0xA8000` 为镜像长度，其后依次是 MD5、名称、长度、魔数）：

```bash
python - <<'PY'
import hashlib
d = open("firmware/iT30ProS_V1.07.bin", "rb").read()
assert len(d) == 688182, len(d)
assert hashlib.md5(d[:0xA8000]).digest() == d[0xA8000:0xA8010], "MD5 不匹配"
assert d[-8:] == bytes.fromhex("AA55669977882233"), "魔数不匹配"
print("OK:", d[0xA8010:0xA802C].decode())
PY
```

预期输出：`OK: iT30ProSiT30SV480S_V1.07.bin`

---

## 第二步：生成补丁固件

```bash
python patches/patch_gr256.py
#   firmware/iT30ProS_V1.07.bin
#     -> firmware/iT30ProS_V1.07_Gr256.bin
```

可用参数：

```bash
python patches/patch_gr256.py --src 输入.bin --dst 输出.bin   # 自定义路径
python patches/patch_gr256.py --no-verify                     # 跳过反汇编报告
```

脚本会依次校验：输入容器 MD5、代码洞区域仍为 `0xFF`（未被占用）、
22 处重定向与 640 字节辅助代码写入成功、重新计算容器 MD5。
使用未经修改的原版输入，输出应当**逐字节可复现**：

```
镜像 MD5  36a1974b9bfadccb9869cdcb87925b64
文件 MD5  de49a9d3a406dc2087a17c61cdcc6280
```

> 早期的 `patch_256_v2.py` / `patch_256_v3.py`（把所有组、含 M 组的上限一并放宽到
> 1/256）已归档到 `tmp/archive/`，**不纳入版本管理**，仅在本地留档。

---

## 第三步：刷写

设备需要先进入**升级（IAP）模式**，两种方式任选：

- **关机状态按住 `MENU` 不松，插入 USB**（最可靠，应用区损坏时同样可用）；
- 开机 → 菜单 → 设备信息 → 固件升级。

进入后设备以 HID 设备枚举：**VID `0x0483` / PID `0x572B`**，
查询返回标识 `Godox_iap_Device`。

```bash
# 1) 确认设备应答（非破坏性）
python skills/godox-it30pro-flash/scripts/godox_iap.py --query

# 2) 干跑：校验容器并构建报文，但不发送
python skills/godox-it30pro-flash/scripts/godox_iap.py \
    --flash firmware/iT30ProS_V1.07_Gr256.bin --i-know-this-bricks --dry-run

# 3) 正式刷写
python skills/godox-it30pro-flash/scripts/godox_iap.py \
    --flash firmware/iT30ProS_V1.07_Gr256.bin --i-know-this-bricks
```

正常输出：

- 擦除阶段收到一个 `0x03` ACK（真实扇区擦除，约 2.1 秒）；
- 写入阶段共 **673 块**，每块都收到 `0x05` ACK；
- 结束后工具**主动保持静默**，等设备自行收尾重启。

**每一块都必须收到 ACK**。工具在第一个缺失 ACK 时立即中止，
因此即使中途失败，只要重新进入 IAP 模式再刷一次即可恢复。

刷写前请**关闭官方 Godox 升级器**——它会独占同一个 HID 设备。

### 恢复原厂固件

用同样的方式刷回未修改的容器：

```bash
python skills/godox-it30pro-flash/scripts/godox_iap.py \
    --flash firmware/iT30ProS_V1.07.bin --i-know-this-bricks
```

IAP 引导程序位于可写镜像之外，刷写永远不会覆盖它，所以设备总能重新进入升级模式。

---

## 第四步：上机验证

1. 进入 **Gr** 模式，选择 **A / B / C** 组：
   触屏滑动条、触屏 `+` / `-`、波轮旋钮、以及 ALL 全组调节，
   都应当能调到 **`1/256`**，且断电重启后保持。
2. 选择 **M** 组（本机功率）：
   下限必须仍为 **`1/128`**；开启 HSS 高速同步时为 **`1/16`**。
3. 其他模式（TTL、Multi 频闪、接收端）行为必须与刷写前完全一致。

> **版本号不会变化**——版本字符串来自 IAP 引导程序（`0xA0` 查询响应），
> 不在可写镜像内。**请用功能行为验证，不要看版本号。**

---

## 工作原理（简述）

每组功率以「衰减量」形式存于 RAM `byte_2000058C[组]`，单位为 1/10 档：

| 数值 | 显示 | 说明 |
|---|---|---|
| `0` | `1/1` | 满功率 |
| `70` (`0x46`) | `1/128` | 官方下限 |
| `80` (`0x50`) | `1/256` | 本补丁放开的值 |
| `0xFF` | `OFF` | 组关闭 |

显示是数学公式 `分母 = 512 >> ((90 - tenths) / 10)`，**不是图标资源**，所以无需改动 UI 素材。

原厂把该值钳制在 `0x46`，且分散在**三个互相独立的层**，任何一层都会把档位卡在 1/128：

1. **取值钳位**：配置校验器 `sub_800AA2C`、配置加载 `sub_800D048`、渲染 `sub_800ABCC` 等；
2. **滑条范围与换算**：`sub_803D014` 里的 `max = 71`、1/3 档上限 `21` 及 `70 - 值` 反算；
3. **步进函数**：`sub_8014E40` 尾部对所有步进结果做统一上限——波轮、触屏 `+`/`-`、
   ALL 全组调节全部经过这里（这正是早期版本"触屏能调、波轮不能"的原因）。

`patch_gr256.py` 没有逐条改写这些限幅序列（它们夹着 `IT` 块和 PC 相对取字面量，
长度也不够插入新指令），而是：

- 在镜像尾部未使用的 `0x0808FA80` 起（原为 `0xFF`）写入 640 字节辅助例程；
- 把原来的 22 个限幅点替换成 `BL` / `B.W` 跳转（其余字节用 `NOP` 填充）。

每个辅助例程读取**实时模式字节** `byte_200003D8`（`3` = Gr）与**组号**，然后给出上限：

```
上限 = 0x46                       # 1/128：M 组，以及所有非 Gr 模式
若 模式 == Gr 且 组号 ∈ 1..3：
    上限 = 0x50                   # 1/256：A / B / C
若 非 Gr 模式 且 HSS 开启：
    上限 = 0x28                   # 1/16：保持原厂行为
```

辅助例程在不允许改动标志位的地方（部分调用点依赖限幅指令产生的条件码）刻意绕开 `CPSR`，
并且保留各调用点实际观测的寄存器。

**未改动**：Multi 频闪（`byte_20000598`）、无线接收路径、以及所有非 Gr 模式。

完整细节（容器格式、内存映射、限幅点全表、逐点说明）见
[`docs/power-model.md`](docs/power-model.md)；
刷写协议与操作规则见
[`skills/godox-it30pro-flash/SKILL.md`](skills/godox-it30pro-flash/SKILL.md)。

---

## 常见问题

| 现象 | 原因与处理 |
|---|---|
| 查询无响应 | 设备还在正常模式，而非升级模式；或官方升级器正占用 HID 设备 |
| `cmd 0 query failed` | 同上。关机 → 按住 `MENU` → 插 USB 重试 |
| 擦除无响应 | 擦除耗时约 2.1 秒，请等待 ≥ 25 秒；仍无响应则重新进升级模式 |
| 刷写中途 `NO ACK` | 设备状态异常。重新进入升级模式后再刷；已写入的部分会在下一次刷写时被完整覆盖 |
| 刷完版本号没变 | **正常现象**。版本来自 IAP 引导程序，刷写不会覆盖它——请用 1/256 档位验证 |
| 触屏能到 1/256，波轮不能 | 你刷的是 V1.09 系列旧补丁。请使用 `patches/patch_gr256.py` 生成的固件 |
| 档位能选 1/256 但实际光量不变 | 本机灯头（M 组）驱动表原生覆盖到 1/512，属正常；作为主控引闪时由从灯决定实际输出 |
| 触屏卡死 / 反复重启 | 补丁中有指令编码错误（尤其是 `IT` 块掩码）。请确认使用本仓库脚本重新生成，而不是历史手工补丁 |
| 调完 1/256 又被拉回 1/128 | 有未被覆盖的钳位点在保存/开机时生效。请反馈具体入口，优先检查 `0x0801EB28` |

---

## 合规与许可

### 许可证

除另有说明外，本仓库的**源码与文档**采用
**GNU General Public License v3.0 或更高版本**（GPL-3.0-or-later）授权，
完整条款见 [LICENSE](LICENSE)。

```
Copyright (C) 2026  iT30Pro S Patch Toolkit contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

GPL 只覆盖**本仓库作者编写的内容**，不覆盖也不授予任何神牛官方固件、
升级包、手册或商标的权利——这些内容不在本仓库中，也不随本仓库分发。

### 合规提醒

- 请仅在**你合法拥有**的设备上使用。
- 固件修改可能违反部分地区关于无线电设备的技术规范；请自行确认当地法规。
- 本项目不提供、也不应被用于规避版权保护或技术保护措施。
- 若你是权利人并认为本仓库存在侵权内容，请提出 issue 以便处理。
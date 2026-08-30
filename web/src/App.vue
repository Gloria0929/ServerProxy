<template>
  <main v-if="sessionChecked && !loggedIn" class="login-shell">
    <section class="login-card" aria-labelledby="login-title">
      <div class="brand-lockup">
        <span class="brand-mark">SP</span>
        <span>SERVERPROXY</span>
      </div>
      <h1 id="login-title">代理控制面板</h1>
      <p class="login-copy">
        输入服务启动时设置的访问密钥。密钥不会保存到浏览器。
      </p>
      <form class="login-form" @submit.prevent="login">
        <label for="secret">访问密钥</label>
        <input id="secret" v-model="secret" type="password" autocomplete="current-password" placeholder="输入 SP_SECRET"
          required />
        <p v-if="loginError" class="form-error">{{ loginError }}</p>
        <button class="button primary wide" :disabled="actionLoading" type="submit">
          {{ actionLoading ? "正在验证" : "进入控制台" }}
        </button>
      </form>
      <p class="login-hint">
        默认仅允许本机访问。远程使用请配置 HTTPS 和 IP 白名单。
      </p>
    </section>
  </main>

  <main v-else-if="loggedIn" class="app-shell">
    <aside class="sidebar">
      <div class="sidebar-top">
        <div class="brand-lockup">
          <span class="brand-mark">SP</span><span>SERVERPROXY</span>
        </div>
      </div>
      <nav aria-label="主导航">
        <button v-for="item in navItems" :key="item.id" class="nav-item" :class="{ active: view === item.id }"
          type="button" @click="goView(item.id)">
          {{ item.label }}
        </button>
      </nav>
      <div class="sidebar-bottom">
        <div class="service-state">
          <span class="state-dot"></span><span>控制面板运行中</span>
        </div>
        <button class="text-button" type="button" @click="logout">
          退出会话
        </button>
      </div>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div>
          <h1>
            {{
              view === "overview"
                ? "保持连接，掌握流量。"
                : navItems.find((item) => item.id === view)?.label
            }}
          </h1>
        </div>
      </header>

      <div v-if="loading" class="loading-grid" aria-label="正在加载">
        <div v-for="item in 6" :key="item" class="skeleton"></div>
      </div>

      <template v-else-if="status">
        <section v-if="view === 'overview'" class="page-stack">
          <div class="live-strip">
            <div class="mode-control">
              <span class="state-dot"></span>
              <select class="mode-select" :value="status.mode" @change="onModeChange">
                <option v-for="opt in modeOptions" :key="opt.value" :value="opt.value">
                  {{ opt.label }}
                </option>
              </select>
            </div>
            <span>当前出口：<strong>{{ status.current_proxy }}</strong></span>
            <span>已运行 {{ duration(status.uptime_seconds) }}</span>
            <span>TUN：{{ status.resources.tun }}</span>
          </div>

          <section class="metric-grid" aria-label="实时流量指标">
            <article class="metric-card emphasis">
              <span>下载</span><strong>{{ bytes(status.traffic.download_rate, true) }}</strong><small>累计 {{
                bytes(status.traffic.download_total) }}</small>
            </article>
            <article class="metric-card">
              <span>上传</span><strong>{{ bytes(status.traffic.upload_rate, true) }}</strong><small>累计 {{
                bytes(status.traffic.upload_total) }}</small>
            </article>
            <article class="metric-card">
              <span>内存</span><strong>{{ status.resources.memory_mb }} MB</strong><small>{{ status.resources.goroutines
              }} 个调度协程</small>
            </article>
            <article class="metric-card">
              <span>活动连接</span><strong>{{ connections.length }}</strong><small>由当前规则集处理</small>
            </article>
          </section>

          <section class="dashboard-grid">
            <article class="panel traffic-panel">
              <div class="panel-heading">
                <div>
                  <h2>最近一分钟</h2>
                </div>
                <span class="muted">每秒刷新</span>
              </div>
              <div class="traffic-chart" aria-label="上传和下载速率柱状图">
                <div v-for="point in metrics.slice(-32)" :key="point.time" class="bar-pair">
                  <i class="bar download" :style="{
                    height: `${Math.max(5, (point.download / chartMax) * 100)}%`,
                  }"></i>
                  <i class="bar upload" :style="{
                    height: `${Math.max(3, (point.upload / chartMax) * 100)}%`,
                  }"></i>
                </div>
              </div>
              <div class="chart-legend">
                <span><i class="legend-swatch download"></i>下载</span><span><i class="legend-swatch upload"></i>上传</span>
              </div>
            </article>

            <article class="panel selected-panel">
              <div class="panel-heading">
                <div>
                  <h2>{{ selectedGroup?.name }}</h2>
                </div>
                <button class="text-button" type="button" @click="goView('proxies')">
                  管理节点
                </button>
              </div>
              <template v-if="selectedGroup">
                <div class="selected-node">
                  <div>
                    <span>已选节点</span><strong>{{
                      selectedGroup?.nodes?.find(
                        (node) => node.id === selectedGroup?.selected,
                      )?.name
                    }}</strong>
                  </div>
                  <b>{{
                    selectedGroup?.nodes?.find(
                      (node) => node.id === selectedGroup?.selected,
                    )?.latency
                  }}
                    ms</b>
                </div>
                <div class="node-preview" v-for="node in selectedGroup?.nodes?.slice(0, 3) ?? []" :key="node.id">
                  <span>{{ node.name }}</span><small>{{ node.latency }} ms</small>
                </div>
              </template>
            </article>
          </section>

          <section class="dashboard-grid lower">
            <article class="panel activity-panel">
              <div class="panel-heading">
                <div>
                  <h2>控制面事件</h2>
                </div>
                <button class="text-button" type="button" @click="goView('logs')">
                  全部日志
                </button>
              </div>
              <div class="activity-list">
                <div v-for="item in logs.slice(0, 4)" :key="item.id" class="activity-row">
                  <span class="log-level" :class="item.level">{{
                    item.level
                  }}</span>
                  <div>
                    <strong>{{ item.message }}</strong><small>{{ item.component }} ·
                      {{ relativeTime(item.time) }}</small>
                  </div>
                </div>
              </div>
            </article>
            <article class="panel quick-panel">
              <h2>降低日常维护成本</h2>
              <div class="quick-actions">
                <button class="button quiet" type="button" :disabled="actionLoading" @click="delayTest">
                  测速全部节点</button><button class="button quiet" type="button" @click="goView('config')">
                  检查配置</button><button class="button quiet" type="button" @click="goView('rules')">
                  查看规则状态
                </button>
              </div>
            </article>
          </section>
        </section>

        <section v-else-if="view === 'proxies'" class="page-stack">
          <div class="page-intro">
            <p>Selector 切换直接同步到内核，不会触发全量配置重载。</p>
            <button class="button primary" type="button" :disabled="actionLoading" @click="delayTest">
              测速全部节点
            </button>
          </div>
          <article v-if="manualGroup" class="panel group-panel">
            <div class="panel-heading">
              <div>
                <h2>{{ activeSubName ? `${activeSubName} 节点` : "代理节点" }}</h2>
              </div>
              <span class="muted">已选择 {{ selectedProxyName }}</span>
            </div>
            <div class="node-table">
              <button v-if="autoGroup" class="node-row" :class="{ selected: manualGroup.selected === 'auto' }"
                type="button" :disabled="actionLoading || manualGroup.selected === 'auto'" @click="selectAuto">
                <span class="node-main"><b>自动</b><small>跟随自动测速 · 当前 {{ autoPickName }}</small></span>
                <span class="node-latency">{{ autoPickLatency }}</span><span class="selection-state">{{
                  manualGroup.selected === "auto" ? "当前使用" : "切换"
                  }}</span>
              </button>
              <button v-for="node in manualNodes" :key="node.id" class="node-row" :class="{
                selected: manualGroup.selected === node.id,
                unavailable: !node.available,
              }" type="button" :disabled="actionLoading || !node.available || manualGroup.selected === node.id"
                @click="selectNode(manualGroup, node)">
                <span class="node-main"><b>{{ node.name }}</b><small>{{ node.protocol }} · {{ node.region
                }}</small></span><span class="node-latency">{{
                      node.available ? `${node.latency} ms` : "不可用"
                    }}</span><span class="selection-state">{{
                    manualGroup.selected === node.id ? "当前使用" : "切换"
                  }}</span>
              </button>
            </div>
          </article>
        </section>

        <section v-else-if="view === 'subscriptions'" class="page-stack">
          <div class="page-intro">
            <p>订阅更新以快照方式保存。失败时保留上一份成功节点。</p>
            <button class="button primary" type="button" :disabled="actionLoading" @click="updateAll">
              更新全部
            </button>
          </div>
          <article class="panel form-panel">
            <div class="panel-heading">
              <div>
                <h2>添加来源</h2>
              </div>
            </div>
            <form class="inline-form" @submit.prevent="addSubscription">
              <label><span>名称</span><input v-model="newSubscription.name" required
                  placeholder="例如：工作订阅" /></label><label class="wide-input"><span>订阅地址</span><input
                  v-model="newSubscription.url" required type="url"
                  placeholder="https://example.com/subscription" /></label>
              <!-- <label>
                <span>频率</span>
                <select v-model="newSubscription.schedule">
                  <option>每 6 小时</option>
                  <option>每天</option>
                </select>
              </label> -->
              <button class="button quiet" type="submit" :disabled="actionLoading">
                添加订阅
              </button>
            </form>
          </article>
          <div class="subscription-grid">
            <article v-for="item in subscriptions" :key="item.id" class="panel subscription-card" :class="{
              selected: selectedSubId === item.id,
            }" role="button" tabindex="0" @click="selectedSubId = item.id" @keydown.enter="selectedSubId = item.id">
              <div>
                <div class="subscription-title">
                  <span class="health-dot" :class="item.status"></span>
                  <h2>{{ item.name }}</h2>
                </div>
                <p>{{ item.url_preview }}</p>
              </div>
              <div class="subscription-meta">
                <span>{{ item.nodes }} 个节点</span><span>{{ item.schedule }}</span><span>更新于 {{
                  relativeTime(item.last_updated)
                }}</span><span v-if="item.warnings">{{ item.warnings }} 个转换提示</span>
              </div>
              <div class="button-group">
                <button class="button quiet" type="button" :disabled="actionLoading"
                  @click.stop="updateSubscription(item)">
                  立即更新
                </button>
                <button class="button quiet" type="button" @click.stop="startEdit(item)">
                  编辑
                </button>
                <button class="button quiet" type="button" @click.stop="deleteSubscription(item)">
                  删除
                </button>
              </div>
            </article>
          </div>
        </section>

        <section v-else-if="view === 'rules'" class="page-stack">
          <div class="page-intro">
            <p>使用 sing-box 原生规则集。首次启动读取缓存，后台按计划更新。</p>
          </div>
          <article v-for="item in ruleSets" :key="item.id" class="panel rule-card">
            <div>
              <div class="subscription-title">
                <span class="health-dot" :class="item.status"></span>
                <h2>{{ item.name }}</h2>
              </div>
              <p>{{ item.source }}</p>
            </div>
            <div class="subscription-meta">
              <span>{{ item.format }}</span><span>{{ item.schedule }}</span><span>更新于 {{ relativeTime(item.last_updated)
              }}</span>
            </div>
            <button class="button quiet" type="button" :disabled="actionLoading" @click="updateRuleSet(item)">
              更新规则集
            </button>
          </article>
          <article class="panel guidance">
            <h2>基础规则进入可视化层，高级逻辑保留 JSON 编辑。</h2>
            <p>
              当前原型已实现规则集更新状态。规则优先级、匹配器与动作会在接入内核适配器后编译到候选配置。
            </p>
          </article>
        </section>

        <section v-else-if="view === 'connections'" class="page-stack">
          <div class="page-intro">
            <p>连接列表默认脱敏，仅显示决策所需信息。</p>
            <span class="muted">{{ connections.length }} 个活动连接</span>
          </div>
          <article class="panel table-panel">
            <div v-if="connections.length" class="connection-list">
              <div v-for="item in connections" :key="item.id" class="connection-row">
                <div>
                  <b>{{ item.target }}</b><small>{{ item.source }} · {{ relativeTime(item.started) }}</small>
                </div>
                <div>
                  <span>{{ item.outbound }}</span><small>规则：{{ item.rule }}</small>
                </div>
                <div>
                  <span>{{ bytes(item.download) }} ↓</span><small>{{ bytes(item.upload) }} ↑</small>
                </div>
                <button class="text-button danger" type="button" @click="closeConnection(item)">
                  断开
                </button>
              </div>
            </div>
            <div v-else class="empty-state">
              <h2>没有活动连接</h2>
              <p>新的代理连接会实时出现在这里。</p>
            </div>
          </article>
        </section>

        <section v-else-if="view === 'logs'" class="page-stack">
          <div class="filter-row">
            <label><span>搜索</span><input v-model="logQuery" placeholder="组件或内容" /></label><label><span>等级</span><select
                v-model="logLevel">
                <option value="">全部</option>
                <option value="info">info</option>
                <option value="warn">warn</option>
                <option value="error">error</option>
              </select></label><button class="button quiet" type="button" @click="load">
              刷新日志
            </button><button class="button quiet" type="button" :disabled="actionLoading" @click="clearLogs">
              清除日志
            </button>
          </div>
          <article class="panel log-panel">
            <div v-if="filteredLogs.length" class="log-list">
              <div v-for="item in filteredLogs" :key="item.id" class="log-row">
                <time>{{
                  new Date(item.time).toLocaleTimeString("zh-CN", {
                    hour12: false,
                  })
                }}</time><span class="log-level" :class="item.level">{{
                    item.level
                  }}</span><span class="log-component">{{ item.component }}</span><span>{{ item.message }}</span>
              </div>
            </div>
            <div v-else class="empty-state">
              <h2>没有匹配的日志</h2>
              <p>调整筛选条件后再试。</p>
            </div>
          </article>
        </section>

        <section v-else-if="view === 'config'" class="page-stack">
          <div class="page-intro">
            <p>每次应用都会创建不可变版本。无效 JSON 会在应用前被阻断。</p>
            <div class="button-group">
              <button class="button quiet" type="button" :disabled="actionLoading" @click="validateConfig">
                校验 JSON</button><button class="button quiet" type="button" :disabled="actionLoading"
                @click="applyConfig">
                应用配置</button><button class="button quiet" type="button" :disabled="actionLoading" @click="reload">
                重载配置
              </button>
            </div>
          </div>
          <p v-if="validation" class="validation-message">{{ validation }}</p>
          <article class="editor-shell">
            <label for="config-draft">托管配置草稿</label><textarea id="config-draft" v-model="configDraft"
              spellcheck="false"></textarea>
          </article>
          <article class="panel revision-panel">
            <div class="panel-heading">
              <div>
                <h2>可回滚修订</h2>
              </div>
            </div>
            <div class="revision-list">
              <div v-for="item in revisions" :key="item.id" class="revision-row">
                <div>
                  <b>{{ item.id }}</b><small>{{ item.summary }}</small>
                </div>
                <span class="state-chip">{{ item.state }}</span><span>{{ relativeTime(item.created_at) }}</span><code>{{
                  item.checksum }}</code><button class="text-button" type="button" :disabled="actionLoading"
                  @click="restoreRevision(item)">
                  恢复
                </button>
              </div>
            </div>
          </article>
        </section>

        <section v-else class="page-stack">
          <article class="panel settings-panel">
            <div class="kernel-section">
              <h3>内核部署</h3>
              <p>
                从官方 Release 下载 sing-box 内核到本机数据目录（bin/）。
                下载完成后用
                <code>--core singbox</code>
                启动，控制面会自动使用已下载的内核。
              </p>
              <button class="button primary" type="button" :disabled="actionLoading" @click="installKernel">
                {{ actionLoading ? "下载中…" : "下载内核" }}
              </button>
            </div>
            <section class="network-section">
              <h2>网络入口</h2>
              <p>
                变更入口设置会重新编译并应用配置，内核将短暂重启。
              </p>
              <div class="setting-row">
                <div>
                  <h3>TUN 虚拟网卡</h3>
                  <p>
                    创建虚拟网卡接管系统全部流量，无需逐应用设置代理。需要管理员权限：macOS / Linux 请用
                    <code>sudo</code>
                    启动面板后再开启。
                  </p>
                </div>
                <label class="switch">
                  <input type="checkbox" :checked="settings?.tun_enabled ?? false" :disabled="actionLoading"
                    @change="toggleTun" /><span class="slider"></span>
                </label>
              </div>
              <dl>
                <div>
                  <dt>Web 监听</dt>
                  <dd>{{ settings?.web_listen ?? "—" }}</dd>
                </div>
                <div>
                  <dt>混合入站</dt>
                  <dd>{{ settings?.mixed_port ?? "—" }}（HTTP/SOCKS）</dd>
                </div>
                <div>
                  <dt>DNS 预设</dt>
                  <dd>{{ settings?.dns_preset ?? "—" }}</dd>
                </div>
              </dl>
            </section>
          </article>
        </section>
      </template>
    </section>

    <div v-if="editingSub" class="modal-overlay" @click.self="cancelEdit">
      <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="edit-title">
        <div class="modal-head">
          <h2 id="edit-title">编辑订阅</h2>
          <button class="text-button" type="button" @click="cancelEdit">
            关闭
          </button>
        </div>
        <form class="modal-form" @submit.prevent="saveSubscription">
          <label>
            <span>名称</span>
            <input v-model="editForm.name" required placeholder="订阅名称" />
          </label>
          <label>
            <span>订阅地址</span>
            <input v-model="editForm.url" required type="url" placeholder="https://..." />
          </label>
          <label>
            <span>频率</span>
            <select v-model="editForm.schedule">
              <option>每 6 小时</option>
              <option>每天</option>
            </select>
          </label>
          <div class="button-group">
            <button class="button primary" type="submit" :disabled="actionLoading">
              保存
            </button>
            <button class="button quiet" type="button" @click="cancelEdit">
              取消
            </button>
          </div>
        </form>
      </div>
    </div>
  </main>

  <main v-else class="boot-shell">
    <div class="loading-grid" aria-label="正在验证会话">
      <div v-for="item in 6" :key="item" class="skeleton"></div>
    </div>
  </main>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { ElMessage } from "element-plus";

type View =
  | "overview"
  | "proxies"
  | "subscriptions"
  | "rules"
  | "connections"
  | "logs"
  | "config"
  | "settings";

const VIEWS: View[] = [
  "overview",
  "proxies",
  "subscriptions",
  "rules",
  "connections",
  "logs",
  "config",
  "settings",
];

interface Traffic {
  upload_rate: number;
  download_rate: number;
  upload_total: number;
  download_total: number;
}

interface Status {
  service: string;
  version: string;
  core_version: string;
  uptime_seconds: number;
  current_proxy: string;
  mode: string;
  traffic: Traffic;
  resources: { memory_mb: number; goroutines: number; tun: string };
}

interface Node {
  id: string;
  name: string;
  protocol: string;
  region: string;
  latency: number;
  available: boolean;
  subscription_id?: string;
}

interface Group {
  tag: string;
  name: string;
  type: string;
  selected: string;
  nodes: Node[];
}

interface Subscription {
  id: string;
  name: string;
  url_preview: string;
  schedule: string;
  enabled: boolean;
  nodes: number;
  last_updated: string;
  status: string;
  warnings: number;
}

interface RuleSet {
  id: string;
  name: string;
  source: string;
  format: string;
  schedule: string;
  last_updated: string;
  status: string;
}

interface Connection {
  id: string;
  source: string;
  target: string;
  outbound: string;
  rule: string;
  upload: number;
  download: number;
  started: string;
}

interface LogEntry {
  id: string;
  time: string;
  level: string;
  component: string;
  message: string;
  seq: number;
}

interface Revision {
  id: string;
  created_at: string;
  state: string;
  summary: string;
  checksum: string;
}

interface PanelSettings {
  web_listen: string;
  mode: string;
  proxy_mode: string;
  whitelist: string[];
  lan_access: boolean;
  tun_enabled: boolean;
  tun_name: string;
  dns_preset: string;
  mixed_port: number;
  trusted_proxies: string[] | null;
  updated_at: string;
}

interface Point {
  time: string;
  upload: number;
  download: number;
}

const navItems: { id: View; label: string }[] = [
  { id: "overview", label: "概览" },
  { id: "proxies", label: "代理节点" },
  { id: "subscriptions", label: "订阅管理" },
  { id: "rules", label: "规则集" },
  { id: "connections", label: "连接" },
  { id: "logs", label: "日志" },
  { id: "config", label: "配置" },
  { id: "settings", label: "设置" },
];

const view = ref<View>("overview");

// 轻量 hash 路由：视图与 URL hash 同步，刷新/前进后退不丢页面。
function goView(next: View) {
  if (view.value !== next) view.value = next;
  const target = `#/${next}`;
  if (location.hash !== target) location.hash = target;
}

function viewFromHash(): View {
  const key = decodeURIComponent(location.hash.replace(/^#\/?/, "")).trim();
  return (VIEWS as string[]).includes(key) ? (key as View) : "overview";
}

function onHashChange() {
  view.value = viewFromHash();
}
const loggedIn = ref(false);
const sessionChecked = ref(false);
const secret = ref("");
const csrf = ref("");
const loading = ref(true);
const actionLoading = ref(false);
const loginError = ref("");
const status = ref<Status | null>(null);
const groups = ref<Group[]>([]);
const subscriptions = ref<Subscription[]>([]);
// 选中的订阅持久化到 localStorage，刷新后高亮与过滤保持一致。
const selectedSubId = ref(localStorage.getItem("sp:selected-sub") ?? "");
watch(selectedSubId, (v) => {
  if (v) localStorage.setItem("sp:selected-sub", v);
  else localStorage.removeItem("sp:selected-sub");
});
const ruleSets = ref<RuleSet[]>([]);
const connections = ref<Connection[]>([]);
const logs = ref<LogEntry[]>([]);
const revisions = ref<Revision[]>([]);
const metrics = ref<Point[]>([]);
const settings = ref<PanelSettings | null>(null);
const logQuery = ref("");
const logLevel = ref("");
const configDraft = ref(`{
  "log": { "level": "info" },
  "inbounds": [],
  "outbounds": [],
  "route": { "rules": [] }
}`);
const validation = ref("");
const newSubscription = ref({ name: "", url: "", schedule: "每 6 小时" });
const editingSub = ref<Subscription | null>(null);
const editForm = ref({ name: "", url: "", schedule: "每 6 小时" });
const modeOptions = [
  { value: "rule", label: "规则模式" },
  { value: "global", label: "全局模式" },
  { value: "direct", label: "直连模式" },
];
let eventSource: EventSource | undefined;

const manualGroup = computed(() =>
  (groups.value ?? []).find((g) => g.type === "selector"),
);
const autoGroup = computed(() =>
  (groups.value ?? []).find((g) => g.type === "urltest"),
);
const selectedGroup = computed(() => manualGroup.value ?? autoGroup.value);
const manualNodes = computed(() => {
  const nodes = manualGroup.value?.nodes?.filter((n) => n.id !== "auto") ?? [];
  if (!selectedSubId.value) return nodes;
  return nodes.filter((n) => n.subscription_id === selectedSubId.value);
});
const activeSubName = computed(() =>
  subscriptions.value.find((s) => s.id === selectedSubId.value)?.name ?? "",
);
const autoPick = computed(() => {
  const auto = autoGroup.value;
  if (!auto) return undefined;
  return auto.nodes?.find((n) => n.id === auto.selected);
});
const autoPickName = computed(
  () => autoPick.value?.name ?? autoGroup.value?.selected ?? "测速中",
);
const autoPickLatency = computed(() =>
  autoPick.value ? `${autoPick.value.latency} ms` : "—",
);
const selectedProxyName = computed(() => {
  const manual = manualGroup.value;
  if (!manual) return "—";
  if (manual.selected === "auto") {
    const pick = autoPickName.value;
    return pick && pick !== "auto" ? `自动（${pick}）` : "自动";
  }
  return (
    manual.nodes?.find((n) => n.id === manual.selected)?.name ??
    manual.selected
  );
});
const chartMax = computed(() =>
  Math.max(
    1,
    ...(metrics.value ?? []).map((item) =>
      Math.max(item.upload, item.download),
    ),
  ),
);
const filteredLogs = computed(() =>
  (logs.value ?? []).filter((item) => {
    const q = logQuery.value.trim().toLowerCase();
    return (
      (!q || `${item.component} ${item.message}`.toLowerCase().includes(q)) &&
      (!logLevel.value || item.level === logLevel.value)
    );
  }),
);

function bytes(value: number, perSecond = false) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = value;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount >= 10 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}${perSecond ? "/s" : ""}`;
}

function relativeTime(value: string) {
  const delta = Math.max(0, Date.now() - new Date(value).getTime());
  const minutes = Math.floor(delta / 60_000);
  if (minutes < 1) return "刚刚";
  if (minutes < 60) return `${minutes} 分钟前`;
  return `${Math.floor(minutes / 60)} 小时前`;
}

function duration(seconds: number) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours ? `${hours} 小时 ${minutes} 分钟` : `${minutes} 分钟`;
}

async function api<T>(url: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (method !== "GET") {
    headers.set("Content-Type", "application/json");
    headers.set("X-CSRF-Token", csrf.value);
  }
  const response = await fetch(`/api/v1${url}`, { ...init, headers });
  if (response.status === 401) {
    loggedIn.value = false;
    stopEvents();
  }
  if (!response.ok) {
    const payload = (await response
      .json()
      .catch(() => ({ message: "请求失败" }))) as { message?: string };
    throw new Error(payload.message ?? "请求失败");
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

async function login() {
  loginError.value = "";
  actionLoading.value = true;
  try {
    const response = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: secret.value }),
    });
    if (!response.ok) throw new Error("访问密钥不正确");
    const result = (await response.json()) as { csrf_token: string };
    csrf.value = result.csrf_token;
    loggedIn.value = true;
    await load();
    startEvents();
    ElMessage.success("登录成功");
  } catch (reason) {
    loginError.value = reason instanceof Error ? reason.message : "无法登录";
  } finally {
    actionLoading.value = false;
  }
}

async function checkSession() {
  try {
    const result = await api<{ csrf_token?: string }>("/auth/session");
    if (result?.csrf_token) csrf.value = result.csrf_token;
    loggedIn.value = true;
  } catch {
    loggedIn.value = false;
  } finally {
    // 会话探测完成前显示加载骨架而非登录页，避免刷新时登录画面一闪而过。
    sessionChecked.value = true;
  }
}

async function load() {
  loading.value = true;
  try {
    const [
      nextStatus,
      nextGroups,
      nextSubscriptions,
      nextRuleSets,
      nextConnections,
      nextLogs,
      nextRevisions,
      nextMetrics,
      nextSettings,
    ] = await Promise.all([
      api<Status>("/system/status"),
      api<Group[]>("/proxies/groups"),
      api<Subscription[]>("/subscriptions"),
      api<RuleSet[]>("/rule-sets"),
      api<Connection[]>("/connections"),
      api<LogEntry[]>("/logs"),
      api<Revision[]>("/config/revisions"),
      api<Point[]>("/metrics/history"),
      api<PanelSettings>("/settings"),
    ]);
    status.value = nextStatus;
    groups.value = nextGroups ?? [];
    subscriptions.value = nextSubscriptions ?? [];
    // 仅一个订阅时默认选中；选中项失效时回退到唯一订阅。
    const subs = nextSubscriptions ?? [];
    if (subs.length === 1) {
      selectedSubId.value = subs[0].id;
    } else if (
      selectedSubId.value &&
      !subs.some((s) => s.id === selectedSubId.value)
    ) {
      selectedSubId.value = "";
    }
    ruleSets.value = nextRuleSets ?? [];
    connections.value = nextConnections ?? [];
    mergeLogs(nextLogs ?? []);
    revisions.value = nextRevisions ?? [];
    metrics.value = nextMetrics ?? [];
    settings.value = nextSettings ?? null;
  } catch (reason) {
    ElMessage.error(
      reason instanceof Error ? reason.message : "无法加载管理数据",
    );
  } finally {
    loading.value = false;
  }
}

function startEvents() {
  stopEvents();
  eventSource = new EventSource("/api/v1/events");
  eventSource.addEventListener("status", (event) => {
    status.value = JSON.parse((event as MessageEvent).data) as Status;
  });
  eventSource.addEventListener("logs", (event) => {
    const fresh = JSON.parse((event as MessageEvent).data) as LogEntry[];
    if (fresh?.length) mergeLogs(fresh);
  });
  eventSource.onerror = () => {
    eventSource?.close();
    // 服务重启或网络抖动后自动重连，避免面板长期停在旧数据。
    window.setTimeout(() => {
      if (loggedIn.value) startEvents();
    }, 3000);
  };
}

function stopEvents() {
  eventSource?.close();
  eventSource = undefined;
}

// 按 id 去重合并日志（含 SSE 增量），按时间倒序保留最近 1000 条。
function mergeLogs(fresh: LogEntry[]) {
  const merged = new Map<string, LogEntry>();
  for (const item of [...logs.value, ...fresh]) merged.set(item.id, item);
  logs.value = [...merged.values()]
    .sort((a, b) => b.time.localeCompare(a.time))
    .slice(0, 1000);
}

async function doAction(label: string, action: () => Promise<unknown>) {
  actionLoading.value = true;
  try {
    await action();
    await load();
    ElMessage.success(`${label}已完成`);
  } catch (reason) {
    ElMessage.error(reason instanceof Error ? reason.message : `${label}失败`);
  } finally {
    actionLoading.value = false;
  }
}

function selectNode(group: Group, node: Node) {
  if (group.type !== "selector") return;
  if (!node.available || group.selected === node.id) return;
  void doAction("节点切换", () =>
    api(`/proxies/groups/${group.tag}/selection`, {
      method: "PATCH",
      body: JSON.stringify({ node_id: node.id }),
    }),
  );
}

function selectAuto() {
  const manual = manualGroup.value;
  if (!manual || manual.selected === "auto") return;
  void doAction("节点切换", () =>
    api(`/proxies/groups/${manual.tag}/selection`, {
      method: "PATCH",
      body: JSON.stringify({ node_id: "auto" }),
    }),
  );
}

function delayTest() {
  void doAction("延迟测试", () =>
    api("/proxies/delay-tests", { method: "POST", body: "{}" }),
  );
}
function updateAll() {
  void doAction("订阅更新", () =>
    api("/subscriptions/all/update", { method: "POST", body: "{}" }),
  );
}
function reload() {
  void doAction("配置重载", () =>
    api("/system/restart", { method: "POST", body: "{}" }),
  );
}
function clearLogs() {
  void doAction("清除日志", async () => {
    await api("/logs", { method: "DELETE" });
    logs.value = [];
  });
}

function toggleTun(event: Event) {
  const enabled = (event.target as HTMLInputElement).checked;
  void doAction(enabled ? "开启 TUN" : "关闭 TUN", () =>
    api("/settings", {
      method: "PATCH",
      body: JSON.stringify({ tun_enabled: enabled }),
    }),
  );
}

function setProxyMode(mode: string) {
  if (!mode || mode === status.value?.mode) return;
  void doAction("模式切换", () =>
    api("/settings", {
      method: "PATCH",
      body: JSON.stringify({ proxy_mode: mode }),
    }),
  );
}
function onModeChange(event: Event) {
  setProxyMode((event.target as HTMLSelectElement).value);
}
function installKernel() {
  void doAction("内核下载", () =>
    api("/system/install-kernel", { method: "POST", body: "{}" }),
  );
}
function updateSubscription(item: Subscription) {
  void doAction("订阅更新", () =>
    api(`/subscriptions/${item.id}/update`, { method: "POST", body: "{}" }),
  );
}
function updateRuleSet(item: RuleSet) {
  void doAction("规则集更新", () =>
    api(`/rule-sets/${item.id}/update`, { method: "POST", body: "{}" }),
  );
}
function closeConnection(item: Connection) {
  if (!window.confirm(`确定断开到 ${item.target} 的连接吗？`)) return;
  void doAction("连接断开", () =>
    api(`/connections/${item.id}`, { method: "DELETE" }),
  );
}

async function startEdit(item: Subscription) {
  editingSub.value = item;
  editForm.value = { name: item.name, url: "", schedule: item.schedule };
  try {
    const detail = await api<{ url: string }>(`/subscriptions/${item.id}`);
    editForm.value.url = detail.url;
  } catch {
    // 取不到明文地址时保持为空，仍可手动填写。
  }
}

function cancelEdit() {
  editingSub.value = null;
}

function saveSubscription() {
  if (!editingSub.value) return;
  const id = editingSub.value.id;
  const payload = {
    name: editForm.value.name,
    url: editForm.value.url,
    schedule: editForm.value.schedule,
  };
  cancelEdit();
  void doAction("订阅保存", () =>
    api(`/subscriptions/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  );
}

function addSubscription() {
  void doAction("订阅添加", async () => {
    const result = await api<Subscription>("/subscriptions", {
      method: "POST",
      body: JSON.stringify(newSubscription.value),
    });
    newSubscription.value = { name: "", url: "", schedule: "每 6 小时" };
    return result;
  });
}

function deleteSubscription(item: Subscription) {
  if (!window.confirm(`确定删除订阅「${item.name}」吗？`)) return;
  void doAction("订阅删除", () =>
    api(`/subscriptions/${item.id}`, { method: "DELETE" }),
  );
}

function validateConfig() {
  void doAction("配置校验", async () => {
    const result = await api<{ message: string }>("/config/validate", {
      method: "POST",
      body: JSON.stringify({ config: configDraft.value }),
    });
    validation.value = result.message;
    return result;
  });
}

function restoreRevision(item: Revision) {
  if (
    !window.confirm(
      `恢复到修订 ${item.id}？会创建新的配置版本并请求内核重载。`,
    )
  )
    return;
  void doAction("版本恢复", () =>
    api(`/config/restore/${item.id}`, { method: "POST", body: "{}" }),
  );
}

function applyConfig() {
  if (!window.confirm("这会创建一个新的配置版本并请求内核重载，是否继续？"))
    return;
  void doAction("配置应用", () =>
    api("/config/apply", {
      method: "POST",
      body: JSON.stringify({ config: configDraft.value }),
    }),
  );
}

async function logout() {
  try {
    await api("/auth/logout", { method: "POST", body: "{}" });
  } finally {
    stopEvents();
    loggedIn.value = false;
    csrf.value = "";
    secret.value = "";
  }
}

onMounted(async () => {
  // 先从 URL hash 恢复上次页面，再探测会话。
  view.value = viewFromHash();
  window.addEventListener("hashchange", onHashChange);
  await checkSession();
  if (loggedIn.value) {
    await load();
    startEvents();
  } else {
    loading.value = false;
  }
});

onBeforeUnmount(() => {
  stopEvents();
  window.removeEventListener("hashchange", onHashChange);
});
</script>

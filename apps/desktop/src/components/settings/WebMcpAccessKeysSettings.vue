<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Copy, CopyCheck, KeyRound, Loader2, Pencil, Plus, RefreshCcw, RotateCw, Trash2, Users, X } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import ErrorBanner from "@/components/ui/ErrorBanner.vue";
import * as api from "@/lib/backend/api";
import type { McpAccessOverview, McpApiKey, McpApiKeyInput, McpIssuedApiKey, McpTeam, McpTeamAccess, McpTeamInput } from "@/lib/backend/api";
import { copyToClipboard } from "@/lib/common/clipboard";
import { useToast } from "@/composables/useToast";

const ACCESS_OPTIONS: McpTeamAccess[] = ["readOnly", "readWrite", "readWriteDangerous"];
const DEFAULT_KEY_PREFIX = "dbxk";
// Mirrors `clean_key_prefix` on the server.
const KEY_PREFIX_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,23}$/;
const NAME_SEPARATOR = /[\s,，]+/;

const { t } = useI18n();
const { toast } = useToast();

const overview = ref<McpAccessOverview | null>(null);
const loading = ref(false);
const working = ref(false);
const error = ref("");

const teamDialogOpen = ref(false);
const editingTeam = ref<McpTeam | null>(null);
const teamForm = ref<McpTeamInput>(emptyTeam());
const teamFormError = ref("");
const connectionFilter = ref("");

const keyDialogOpen = ref(false);
const editingKey = ref<McpApiKey | null>(null);
const keyForm = ref<McpApiKeyInput>(emptyKey());
const keyNames = ref<string[]>([]);
const keyNameDraft = ref("");
const keyNameInput = ref<HTMLInputElement | null>(null);
const keyPrefix = ref("");
const keyExpiresText = ref("");
const keyFormError = ref("");

const issued = ref<McpIssuedApiKey[]>([]);

const teamFilter = ref<string[]>([]);
const selectedKeyIds = ref<string[]>([]);

type PendingAction = { kind: "deleteTeam"; team: McpTeam } | { kind: "deleteKey"; key: McpApiKey } | { kind: "rotateKey"; key: McpApiKey };
const pending = ref<PendingAction | null>(null);

const teams = computed(() => overview.value?.teams ?? []);
const keys = computed(() => overview.value?.keys ?? []);
const teamNames = computed(() => new Map(teams.value.map((team) => [team.id, team.name])));
const connectionNames = computed(() => new Map((overview.value?.connections ?? []).map((connection) => [connection.id, connection.name])));
const groupNames = computed(() => new Map((overview.value?.groups ?? []).map((group) => [group.id, group.name])));
const endpointUrl = computed(() => (overview.value ? `${window.location.origin}${overview.value.endpointPath}` : ""));
const filteredConnections = computed(() => {
  const query = connectionFilter.value.trim().toLowerCase();
  const connections = overview.value?.connections ?? [];
  if (!query) return connections;
  return connections.filter((connection) => [connection.name, connection.dbType, ...connection.groupPath].some((value) => value.toLowerCase().includes(query)));
});
const filteredKeys = computed(() => {
  const filter = teamFilter.value;
  if (!filter.length) return keys.value;
  return keys.value.filter((key) => key.teamIds.some((teamId) => filter.includes(teamId)));
});
const visibleSelectedIds = computed(() => filteredKeys.value.filter((key) => selectedKeyIds.value.includes(key.id)).map((key) => key.id));
const allVisibleSelected = computed(() => filteredKeys.value.length > 0 && visibleSelectedIds.value.length === filteredKeys.value.length);
/** Prefix the server picks when none is typed: first selected team that has one. */
const teamKeyPrefix = computed(() => {
  for (const teamId of keyForm.value.teamIds) {
    const prefix = teams.value.find((team) => team.id === teamId)?.keyPrefix;
    if (prefix) return prefix;
  }
  return DEFAULT_KEY_PREFIX;
});
const keyPrefixPreview = computed(() => `${normalizePrefix(keyPrefix.value) || teamKeyPrefix.value}_xxxxxxxx…`);
const issuedSingle = computed(() => (issued.value.length === 1 ? issued.value[0] : null));
const issuedCopyable = computed(() => issued.value.every((item) => item.key.copyable));
const issuedConfig = computed(() => {
  if (!issuedSingle.value) return "";
  return JSON.stringify({ mcpServers: { dbx: { type: "http", url: endpointUrl.value, headers: { Authorization: `Bearer ${issuedSingle.value.secret}` } } } }, null, 2);
});
const pendingTitle = computed(() => {
  switch (pending.value?.kind) {
    case "deleteTeam":
      return t("mcpAccess.deleteTeamTitle");
    case "deleteKey":
      return t("mcpAccess.deleteKeyTitle");
    case "rotateKey":
      return t("mcpAccess.rotateKeyTitle");
    default:
      return "";
  }
});
const pendingMessage = computed(() => {
  const action = pending.value;
  if (!action) return "";
  if (action.kind === "deleteTeam") return t("mcpAccess.deleteTeamConfirm", { name: action.team.name });
  if (action.kind === "deleteKey") return t("mcpAccess.deleteKeyConfirm", { name: action.key.name });
  return t("mcpAccess.rotateKeyConfirm", { name: action.key.name });
});

function emptyTeam(): McpTeamInput {
  return { name: "", description: "", connectionIds: [], groupIds: [], access: "readOnly", keyPrefix: "" };
}

function emptyKey(): McpApiKeyInput {
  return { name: "", teamIds: [], enabled: true, expiresAt: null };
}

function errorMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

function formatTime(value: number | null | undefined, fallback: string): string {
  return value ? new Date(value).toLocaleString() : fallback;
}

function toDateTimeLocal(value: number | null): string {
  if (!value) return "";
  const date = new Date(value);
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(value - offset).toISOString().slice(0, 16);
}

function toggle(list: string[], id: string): string[] {
  return list.includes(id) ? list.filter((item) => item !== id) : [...list, id];
}

function normalizePrefix(value: string): string {
  return value.trim().replace(/_+$/, "");
}

function prefixError(value: string): string {
  const prefix = normalizePrefix(value);
  return prefix && !KEY_PREFIX_PATTERN.test(prefix) ? t("mcpAccess.keyPrefixInvalid") : "";
}

/** One line per key: `name key`. */
function keyLines(items: { name: string; secret: string }[]): string {
  return items.map((item) => `${item.name} ${item.secret}`).join("\n");
}

function keyStatus(key: McpApiKey): { label: string; variant: "default" | "outline" | "destructive" } {
  if (key.expired) return { label: t("mcpAccess.expired"), variant: "destructive" };
  if (!key.enabled) return { label: t("mcpAccess.disabled"), variant: "outline" };
  return { label: t("mcpAccess.enabled"), variant: "default" };
}

function teamSummary(team: McpTeam): string {
  const names = [...team.connectionIds.map((id) => connectionNames.value.get(id) ?? id), ...team.groupIds.map((id) => `📁 ${groupNames.value.get(id) ?? id}`)];
  return names.join(", ");
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    overview.value = await api.loadMcpAccessOverview();
    const known = new Set(overview.value.keys.map((key) => key.id));
    selectedKeyIds.value = selectedKeyIds.value.filter((id) => known.has(id));
    const knownTeams = new Set(overview.value.teams.map((team) => team.id));
    teamFilter.value = teamFilter.value.filter((id) => knownTeams.has(id));
  } catch (cause) {
    error.value = errorMessage(cause);
  } finally {
    loading.value = false;
  }
}

function openTeam(team: McpTeam | null) {
  editingTeam.value = team;
  teamForm.value = team ? { name: team.name, description: team.description, connectionIds: [...team.connectionIds], groupIds: [...team.groupIds], access: team.access, keyPrefix: team.keyPrefix } : emptyTeam();
  teamFormError.value = "";
  connectionFilter.value = "";
  teamDialogOpen.value = true;
}

async function saveTeam() {
  if (!teamForm.value.name.trim()) {
    teamFormError.value = t("mcpAccess.nameRequired");
    return;
  }
  const invalidPrefix = prefixError(teamForm.value.keyPrefix);
  if (invalidPrefix) {
    teamFormError.value = invalidPrefix;
    return;
  }
  working.value = true;
  teamFormError.value = "";
  try {
    const input = { ...teamForm.value, keyPrefix: normalizePrefix(teamForm.value.keyPrefix) };
    if (editingTeam.value) await api.updateMcpTeam(editingTeam.value.id, input);
    else await api.createMcpTeam(input);
    teamDialogOpen.value = false;
    toast(t("mcpAccess.teamSaved"));
    await load();
  } catch (cause) {
    teamFormError.value = errorMessage(cause);
  } finally {
    working.value = false;
  }
}

function openKey(key: McpApiKey | null) {
  editingKey.value = key;
  keyForm.value = key ? { name: key.name, teamIds: [...key.teamIds], enabled: key.enabled, expiresAt: key.expiresAt } : emptyKey();
  // New keys start with the teams currently filtered on, the usual next step.
  if (!key) keyForm.value.teamIds = [...teamFilter.value];
  keyNames.value = [];
  keyNameDraft.value = "";
  keyPrefix.value = "";
  keyExpiresText.value = toDateTimeLocal(keyForm.value.expiresAt);
  keyFormError.value = "";
  keyDialogOpen.value = true;
  if (!key) void nextTick(() => keyNameInput.value?.focus());
}

/** Moves typed or pasted text into name chips; returns false on a duplicate. */
function addKeyNames(text: string): boolean {
  keyFormError.value = "";
  for (const name of text.split(NAME_SEPARATOR).filter(Boolean)) {
    const lower = name.toLowerCase();
    const duplicate = keyNames.value.some((existing) => existing.toLowerCase() === lower) || keys.value.some((key) => key.name.toLowerCase() === lower);
    if (duplicate) {
      keyFormError.value = t("mcpAccess.duplicateName", { name });
      return false;
    }
    keyNames.value.push(name.slice(0, 100));
  }
  return true;
}

function commitKeyNameDraft(): boolean {
  if (!keyNameDraft.value.trim()) return true;
  const ok = addKeyNames(keyNameDraft.value);
  if (ok) keyNameDraft.value = "";
  return ok;
}

function onKeyNameKeydown(event: KeyboardEvent) {
  if (event.isComposing) return;
  if (event.key === " " || event.key === "Enter" || event.key === "," || event.key === "，") {
    event.preventDefault();
    commitKeyNameDraft();
  } else if (event.key === "Backspace" && !keyNameDraft.value && keyNames.value.length) {
    keyNames.value.pop();
  }
}

function onKeyNamePaste(event: ClipboardEvent) {
  const text = event.clipboardData?.getData("text") ?? "";
  if (!NAME_SEPARATOR.test(text.trim())) return;
  event.preventDefault();
  addKeyNames(`${keyNameDraft.value} ${text}`) && (keyNameDraft.value = "");
}

async function saveKey() {
  const expiresAt = keyExpiresText.value ? new Date(keyExpiresText.value).getTime() : null;
  const normalizedExpiry = expiresAt === null || Number.isNaN(expiresAt) ? null : expiresAt;
  if (editingKey.value) {
    if (!keyForm.value.name.trim()) {
      keyFormError.value = t("mcpAccess.nameRequired");
      return;
    }
  } else {
    if (!commitKeyNameDraft()) return;
    if (!keyNames.value.length) {
      keyFormError.value = t("mcpAccess.nameRequired");
      return;
    }
    const invalidPrefix = prefixError(keyPrefix.value);
    if (invalidPrefix) {
      keyFormError.value = invalidPrefix;
      return;
    }
  }
  working.value = true;
  keyFormError.value = "";
  try {
    if (editingKey.value) {
      await api.updateMcpApiKey(editingKey.value.id, { ...keyForm.value, expiresAt: normalizedExpiry });
      toast(t("mcpAccess.keySaved"));
    } else {
      issued.value = await api.createMcpApiKeys({
        names: keyNames.value,
        teamIds: keyForm.value.teamIds,
        enabled: keyForm.value.enabled,
        expiresAt: normalizedExpiry,
        prefix: normalizePrefix(keyPrefix.value) || null,
      });
    }
    keyDialogOpen.value = false;
    await load();
  } catch (cause) {
    keyFormError.value = errorMessage(cause);
  } finally {
    working.value = false;
  }
}

async function setKeyEnabled(key: McpApiKey, enabled: boolean) {
  working.value = true;
  try {
    await api.updateMcpApiKey(key.id, { name: key.name, teamIds: key.teamIds, enabled, expiresAt: key.expiresAt });
    await load();
  } catch (cause) {
    toast(errorMessage(cause), 5000);
  } finally {
    working.value = false;
  }
}

async function confirmPending() {
  const action = pending.value;
  if (!action) return;
  working.value = true;
  try {
    if (action.kind === "deleteTeam") {
      await api.deleteMcpTeam(action.team.id);
      toast(t("mcpAccess.teamDeleted"));
    } else if (action.kind === "deleteKey") {
      await api.deleteMcpApiKey(action.key.id);
      toast(t("mcpAccess.keyDeleted"));
    } else {
      issued.value = [await api.rotateMcpApiKey(action.key.id)];
    }
    pending.value = null;
    await load();
  } catch (cause) {
    toast(errorMessage(cause), 5000);
  } finally {
    working.value = false;
  }
}

async function copy(value: string) {
  await copyToClipboard(value);
  toast(t("mcpAccess.copied"));
}

/** Copies stored keys as `name key` lines; single keys copy the bare secret. */
async function copyStoredKeys(ids: string[], asLines: boolean) {
  if (!ids.length) return;
  working.value = true;
  try {
    const revealed = await api.revealMcpApiKeys(ids);
    const available = revealed.filter((item): item is { id: string; name: string; secret: string } => Boolean(item.secret));
    const skipped = revealed.length - available.length;
    if (!available.length) {
      toast(t("mcpAccess.notCopyable"), 5000);
      return;
    }
    await copyToClipboard(asLines ? keyLines(available) : available[0].secret);
    toast(skipped ? t("mcpAccess.copiedSkipped", { count: available.length, skipped }) : t("mcpAccess.copiedKeys", { count: available.length }), skipped ? 5000 : undefined);
  } catch (cause) {
    toast(errorMessage(cause), 5000);
  } finally {
    working.value = false;
  }
}

function toggleAllVisible() {
  const visible = filteredKeys.value.map((key) => key.id);
  selectedKeyIds.value = allVisibleSelected.value ? selectedKeyIds.value.filter((id) => !visible.includes(id)) : [...new Set([...selectedKeyIds.value, ...visible])];
}

onMounted(load);
</script>

<template>
  <section class="flex flex-col gap-6 py-2">
    <div class="flex items-start justify-between gap-3">
      <div class="space-y-1">
        <h3 class="text-base font-semibold">{{ t("mcpAccess.title") }}</h3>
        <p class="text-xs text-muted-foreground">{{ t("mcpAccess.description") }}</p>
      </div>
      <Button size="sm" variant="outline" :disabled="loading" @click="load">
        <Loader2 v-if="loading" class="mr-1 h-3.5 w-3.5 animate-spin" />
        <RefreshCcw v-else class="mr-1 h-3.5 w-3.5" />
        {{ t("mcpAccess.refresh") }}
      </Button>
    </div>

    <ErrorBanner v-if="error" :message="error" />

    <template v-if="overview">
      <div class="space-y-1.5">
        <p v-if="!overview.endpointEnabled" class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">{{ t("mcpAccess.endpointDisabled") }}</p>
        <div class="flex min-w-0 items-center gap-2">
          <Label class="shrink-0 text-xs">{{ t("mcpAccess.endpoint") }}</Label>
          <code class="min-w-0 flex-1 overflow-x-auto rounded border bg-background px-2 py-1.5 text-xs">{{ endpointUrl }}</code>
        </div>
      </div>

      <!-- Teams -->
      <div class="space-y-2">
        <div class="flex items-center justify-between gap-3">
          <div>
            <p class="flex items-center gap-1.5 text-sm font-semibold"><Users class="h-4 w-4" />{{ t("mcpAccess.teams") }}</p>
            <p class="text-[11px] text-muted-foreground">{{ t("mcpAccess.teamsDescription") }}</p>
          </div>
          <Button size="sm" :disabled="working" @click="openTeam(null)"><Plus class="mr-1 h-3.5 w-3.5" />{{ t("mcpAccess.createTeam") }}</Button>
        </div>
        <div class="overflow-x-auto rounded-lg border">
          <table class="w-full table-auto text-left text-xs">
            <thead class="bg-muted">
              <tr>
                <th class="px-3 py-2">{{ t("mcpAccess.name") }}</th>
                <th class="px-3 py-2">{{ t("mcpAccess.connections") }}</th>
                <th class="px-3 py-2">{{ t("mcpAccess.access") }}</th>
                <th class="w-px whitespace-nowrap px-3 py-2 text-right">{{ t("mcpAccess.rowActions") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="team in teams" :key="team.id" class="border-t">
                <td class="px-3 py-2">
                  <div class="font-medium">{{ team.name }}</div>
                  <div v-if="team.description" class="max-w-56 truncate text-muted-foreground" :title="team.description">{{ team.description }}</div>
                  <div v-if="team.keyPrefix" class="font-mono text-muted-foreground" :title="t('mcpAccess.keyPrefix')">{{ team.keyPrefix }}_…</div>
                </td>
                <td class="max-w-72 px-3 py-2">
                  <div class="text-muted-foreground">{{ t("mcpAccess.connectionCount", { count: team.connectionIds.length }) }} · {{ t("mcpAccess.groupCount", { count: team.groupIds.length }) }}</div>
                  <div class="truncate" :title="teamSummary(team)">{{ teamSummary(team) || "-" }}</div>
                </td>
                <td class="whitespace-nowrap px-3 py-2">
                  <Badge :variant="team.access === 'readOnly' ? 'secondary' : team.access === 'readWrite' ? 'outline' : 'destructive'">{{ t(`mcpAccess.accessOptions.${team.access}`) }}</Badge>
                </td>
                <td class="w-px whitespace-nowrap px-2 py-2">
                  <div class="flex justify-end gap-1">
                    <Button size="icon-xs" variant="ghost" :title="t('mcpAccess.editTeam')" :disabled="working" @click="openTeam(team)"><Pencil class="h-3.5 w-3.5" /></Button>
                    <Button size="icon-xs" variant="ghost" class="text-destructive" :title="t('mcpAccess.delete')" :disabled="working" @click="pending = { kind: 'deleteTeam', team }"><Trash2 class="h-3.5 w-3.5" /></Button>
                  </div>
                </td>
              </tr>
              <tr v-if="!teams.length">
                <td colspan="4" class="p-6 text-center text-muted-foreground">{{ t("mcpAccess.noTeams") }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Keys -->
      <div class="space-y-2">
        <div class="flex items-center justify-between gap-3">
          <div>
            <p class="flex items-center gap-1.5 text-sm font-semibold"><KeyRound class="h-4 w-4" />{{ t("mcpAccess.keys") }}</p>
            <p class="text-[11px] text-muted-foreground">{{ t("mcpAccess.keysDescription") }}</p>
          </div>
          <Button size="sm" :disabled="working" @click="openKey(null)"><Plus class="mr-1 h-3.5 w-3.5" />{{ t("mcpAccess.createKey") }}</Button>
        </div>
        <div v-if="teams.length" class="flex flex-wrap items-center gap-1.5 text-xs" data-testid="mcp-key-team-filter">
          <span class="mr-1 text-muted-foreground">{{ t("mcpAccess.filterTeams") }}</span>
          <button type="button" class="rounded-full border px-2.5 py-0.5 transition-colors" :class="teamFilter.length ? 'hover:bg-muted' : 'border-primary bg-primary text-primary-foreground'" @click="teamFilter = []">
            {{ t("mcpAccess.allTeams") }}
          </button>
          <button v-for="team in teams" :key="team.id" type="button" class="rounded-full border px-2.5 py-0.5 transition-colors" :class="teamFilter.includes(team.id) ? 'border-primary bg-primary text-primary-foreground' : 'hover:bg-muted'" @click="teamFilter = toggle(teamFilter, team.id)">
            {{ team.name }}
          </button>
        </div>
        <div v-if="visibleSelectedIds.length" class="flex flex-wrap items-center gap-2 rounded-md border bg-muted/50 px-3 py-1.5 text-xs">
          <span>{{ t("mcpAccess.selectedCount", { count: visibleSelectedIds.length }) }}</span>
          <Button size="xs" :disabled="working" data-testid="mcp-copy-selected" @click="copyStoredKeys(visibleSelectedIds, true)"><CopyCheck class="mr-1 h-3.5 w-3.5" />{{ t("mcpAccess.copySelected") }}</Button>
          <Button size="xs" variant="ghost" :disabled="working" @click="selectedKeyIds = []">{{ t("mcpAccess.clearSelection") }}</Button>
          <span class="ml-auto text-muted-foreground">{{ t("mcpAccess.copyFormat") }}</span>
        </div>
        <div class="overflow-x-auto rounded-lg border">
          <table class="w-full table-auto text-left text-xs">
            <thead class="bg-muted">
              <tr>
                <th class="w-px px-3 py-2">
                  <input type="checkbox" :aria-label="t('mcpAccess.selectAll')" :checked="allVisibleSelected" :indeterminate="visibleSelectedIds.length > 0 && !allVisibleSelected" :disabled="!filteredKeys.length" @change="toggleAllVisible" />
                </th>
                <th class="px-3 py-2">{{ t("mcpAccess.name") }}</th>
                <th class="px-3 py-2">{{ t("mcpAccess.teams") }}</th>
                <th class="px-3 py-2">{{ t("mcpAccess.status") }}</th>
                <th class="px-3 py-2">{{ t("mcpAccess.expiresAt") }}</th>
                <th class="px-3 py-2">{{ t("mcpAccess.lastUsed") }}</th>
                <th class="w-px whitespace-nowrap px-3 py-2 text-right">{{ t("mcpAccess.rowActions") }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="key in filteredKeys" :key="key.id" class="border-t" :class="selectedKeyIds.includes(key.id) ? 'bg-muted/40' : ''">
                <td class="w-px px-3 py-2">
                  <input type="checkbox" :aria-label="key.name" :checked="selectedKeyIds.includes(key.id)" @change="selectedKeyIds = toggle(selectedKeyIds, key.id)" />
                </td>
                <td class="px-3 py-2">
                  <div class="font-medium">{{ key.name }}</div>
                  <div class="font-mono text-muted-foreground">{{ key.prefix }}…</div>
                </td>
                <td class="max-w-56 px-3 py-2">
                  <div class="flex flex-wrap gap-1">
                    <Badge v-for="teamId in key.teamIds" :key="teamId" variant="outline">{{ teamNames.get(teamId) ?? teamId }}</Badge>
                    <span v-if="!key.teamIds.length" class="text-muted-foreground">{{ t("mcpAccess.noTeamsBound") }}</span>
                  </div>
                </td>
                <td class="whitespace-nowrap px-3 py-2">
                  <Badge :variant="keyStatus(key).variant">{{ keyStatus(key).label }}</Badge>
                </td>
                <td class="whitespace-nowrap px-3 py-2">{{ formatTime(key.expiresAt, t("mcpAccess.never")) }}</td>
                <td class="whitespace-nowrap px-3 py-2" :title="`${t('mcpAccess.created')}: ${formatTime(key.createdAt, '-')}`">{{ formatTime(key.lastUsedAt, t("mcpAccess.neverUsed")) }}</td>
                <td class="w-px whitespace-nowrap px-2 py-2">
                  <div class="flex items-center justify-end gap-1">
                    <Switch :model-value="key.enabled" :disabled="working" :title="key.enabled ? t('mcpAccess.disable') : t('mcpAccess.enable')" @update:model-value="(value: boolean) => setKeyEnabled(key, value)" />
                    <Button size="icon-xs" variant="ghost" :title="key.copyable ? t('mcpAccess.copyKey') : t('mcpAccess.notCopyable')" :disabled="working || !key.copyable" data-testid="mcp-copy-key" @click="copyStoredKeys([key.id], false)"><Copy class="h-3.5 w-3.5" /></Button>
                    <Button size="icon-xs" variant="ghost" :title="t('mcpAccess.editKey')" :disabled="working" @click="openKey(key)"><Pencil class="h-3.5 w-3.5" /></Button>
                    <Button size="icon-xs" variant="ghost" :title="t('mcpAccess.rotate')" :disabled="working" @click="pending = { kind: 'rotateKey', key }"><RotateCw class="h-3.5 w-3.5" /></Button>
                    <Button size="icon-xs" variant="ghost" class="text-destructive" :title="t('mcpAccess.delete')" :disabled="working" @click="pending = { kind: 'deleteKey', key }"><Trash2 class="h-3.5 w-3.5" /></Button>
                  </div>
                </td>
              </tr>
              <tr v-if="!filteredKeys.length">
                <td colspan="7" class="p-6 text-center text-muted-foreground">{{ keys.length ? t("mcpAccess.noKeysMatch") : t("mcpAccess.noKeys") }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <!-- Team dialog -->
    <Dialog v-model:open="teamDialogOpen">
      <DialogContent class="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{{ editingTeam ? t("mcpAccess.editTeam") : t("mcpAccess.createTeam") }}</DialogTitle>
        </DialogHeader>
        <ErrorBanner v-if="teamFormError" :message="teamFormError" />
        <div class="grid max-h-[62vh] gap-4 overflow-y-auto pr-1 text-xs">
          <label class="grid gap-1">
            <span class="font-medium">{{ t("mcpAccess.name") }}</span>
            <Input v-model="teamForm.name" maxlength="100" />
          </label>
          <label class="grid gap-1">
            <span class="font-medium">{{ t("mcpAccess.descriptionLabel") }}</span>
            <Input v-model="teamForm.description" maxlength="500" />
          </label>
          <label class="grid gap-1">
            <span class="font-medium">{{ t("mcpAccess.keyPrefix") }}</span>
            <Input v-model="teamForm.keyPrefix" class="w-64 font-mono" maxlength="24" placeholder="dbxk" />
            <span class="text-[11px] text-muted-foreground">{{ t("mcpAccess.teamKeyPrefixHelp", { example: `${normalizePrefix(teamForm.keyPrefix) || "dbxk"}_xxxxxxxx…` }) }}</span>
          </label>
          <div class="grid gap-1">
            <span class="font-medium">{{ t("mcpAccess.access") }}</span>
            <Select v-model="teamForm.access">
              <SelectTrigger class="w-64"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem v-for="option in ACCESS_OPTIONS" :key="option" :value="option">{{ t(`mcpAccess.accessOptions.${option}`) }}</SelectItem>
              </SelectContent>
            </Select>
            <span class="text-[11px] text-muted-foreground">{{ t("mcpAccess.accessHelp") }}</span>
          </div>
          <div class="grid gap-1">
            <div class="flex items-center justify-between gap-2">
              <span class="font-medium">{{ t("mcpAccess.connections") }}</span>
              <span class="text-muted-foreground">{{ t("mcpAccess.selectedCount", { count: teamForm.connectionIds.length }) }}</span>
            </div>
            <Input v-model="connectionFilter" :placeholder="t('mcpAccess.searchConnections')" />
            <div class="max-h-48 overflow-y-auto rounded-md border p-1">
              <label v-for="connection in filteredConnections" :key="connection.id" class="flex cursor-pointer items-center gap-2 rounded px-2 py-1 hover:bg-muted">
                <input type="checkbox" :checked="teamForm.connectionIds.includes(connection.id)" @change="teamForm.connectionIds = toggle(teamForm.connectionIds, connection.id)" />
                <span class="truncate">{{ connection.name }}</span>
                <span class="shrink-0 text-muted-foreground">{{ connection.dbType }}</span>
                <span v-if="connection.groupPath.length" class="ml-auto truncate text-muted-foreground">{{ connection.groupPath.join(" / ") }}</span>
              </label>
              <p v-if="!filteredConnections.length" class="px-2 py-3 text-center text-muted-foreground">{{ t("mcpAccess.noConnections") }}</p>
            </div>
          </div>
          <div class="grid gap-1">
            <div class="flex items-center justify-between gap-2">
              <span class="font-medium">{{ t("mcpAccess.groups") }}</span>
              <span class="text-muted-foreground">{{ t("mcpAccess.selectedCount", { count: teamForm.groupIds.length }) }}</span>
            </div>
            <div class="max-h-36 overflow-y-auto rounded-md border p-1">
              <label v-for="group in overview?.groups ?? []" :key="group.id" class="flex cursor-pointer items-center gap-2 rounded px-2 py-1 hover:bg-muted">
                <input type="checkbox" :checked="teamForm.groupIds.includes(group.id)" @change="teamForm.groupIds = toggle(teamForm.groupIds, group.id)" />
                <span class="truncate">{{ group.name }}</span>
              </label>
              <p v-if="!(overview?.groups ?? []).length" class="px-2 py-3 text-center text-muted-foreground">{{ t("mcpAccess.noGroups") }}</p>
            </div>
            <span class="text-[11px] text-muted-foreground">{{ t("mcpAccess.groupsHelp") }}</span>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" :disabled="working" @click="teamDialogOpen = false">{{ t("mcpAccess.cancel") }}</Button>
          <Button :disabled="working" @click="saveTeam"><Loader2 v-if="working" class="mr-1 h-3.5 w-3.5 animate-spin" />{{ t("mcpAccess.save") }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Key dialog -->
    <Dialog v-model:open="keyDialogOpen">
      <DialogContent class="max-w-lg">
        <DialogHeader>
          <DialogTitle>{{ editingKey ? t("mcpAccess.editKey") : t("mcpAccess.createKey") }}</DialogTitle>
        </DialogHeader>
        <ErrorBanner v-if="keyFormError" :message="keyFormError" />
        <div class="grid max-h-[62vh] gap-4 overflow-y-auto pr-1 text-xs">
          <label v-if="editingKey" class="grid gap-1">
            <span class="font-medium">{{ t("mcpAccess.name") }}</span>
            <Input v-model="keyForm.name" maxlength="100" />
          </label>
          <div v-else class="grid gap-1">
            <div class="flex items-center justify-between gap-2">
              <span class="font-medium">{{ t("mcpAccess.keyNames") }}</span>
              <span class="text-muted-foreground">{{ t("mcpAccess.selectedCount", { count: keyNames.length }) }}</span>
            </div>
            <div class="flex min-h-9 cursor-text flex-wrap items-center gap-1 rounded-md border bg-background px-2 py-1 focus-within:ring-1 focus-within:ring-ring" data-testid="mcp-key-names" @click="keyNameInput?.focus()">
              <span v-for="(name, index) in keyNames" :key="name" class="inline-flex items-center gap-0.5 rounded-full bg-primary/10 py-0.5 pl-2 pr-1 text-primary">
                {{ name }}
                <button type="button" class="rounded-full p-0.5 hover:bg-primary/20" :aria-label="t('mcpAccess.delete')" @click.stop="keyNames.splice(index, 1)"><X class="h-3 w-3" /></button>
              </span>
              <input ref="keyNameInput" v-model="keyNameDraft" class="min-w-32 flex-1 bg-transparent py-0.5 outline-none" maxlength="100" :placeholder="keyNames.length ? '' : t('mcpAccess.keyNamesPlaceholder')" @keydown="onKeyNameKeydown" @paste="onKeyNamePaste" @blur="commitKeyNameDraft" />
            </div>
            <span class="text-[11px] text-muted-foreground">{{ t("mcpAccess.keyNamesHelp") }}</span>
          </div>
          <div class="grid gap-1">
            <span class="font-medium">{{ t("mcpAccess.teams") }}</span>
            <div class="max-h-40 overflow-y-auto rounded-md border p-1">
              <label v-for="team in teams" :key="team.id" class="flex cursor-pointer items-center gap-2 rounded px-2 py-1 hover:bg-muted">
                <input type="checkbox" :checked="keyForm.teamIds.includes(team.id)" @change="keyForm.teamIds = toggle(keyForm.teamIds, team.id)" />
                <span class="truncate">{{ team.name }}</span>
                <span v-if="team.keyPrefix" class="shrink-0 font-mono text-muted-foreground">{{ team.keyPrefix }}_</span>
                <span class="ml-auto shrink-0 text-muted-foreground">{{ t(`mcpAccess.accessOptions.${team.access}`) }}</span>
              </label>
              <p v-if="!teams.length" class="px-2 py-3 text-center text-muted-foreground">{{ t("mcpAccess.noTeams") }}</p>
            </div>
            <span class="text-[11px] text-muted-foreground">{{ t("mcpAccess.keyTeamsHelp") }}</span>
          </div>
          <label v-if="!editingKey" class="grid gap-1">
            <span class="font-medium">{{ t("mcpAccess.keyPrefix") }}</span>
            <Input v-model="keyPrefix" class="w-64 font-mono" maxlength="24" :placeholder="teamKeyPrefix" data-testid="mcp-key-prefix" />
            <span class="text-[11px] text-muted-foreground"
              >{{ t("mcpAccess.keyPrefixHelp") }} <code class="font-mono">{{ keyPrefixPreview }}</code></span
            >
          </label>
          <div class="grid gap-1">
            <span class="font-medium">{{ t("mcpAccess.expiresAt") }}</span>
            <div class="flex gap-2">
              <Input v-model="keyExpiresText" type="datetime-local" />
              <Button variant="outline" size="sm" :disabled="!keyExpiresText" @click="keyExpiresText = ''">{{ t("mcpAccess.clear") }}</Button>
            </div>
            <span class="text-[11px] text-muted-foreground">{{ t("mcpAccess.expiresAtHelp") }}</span>
          </div>
          <div class="flex items-center justify-between gap-3">
            <Label for="mcp-key-enabled">{{ t("mcpAccess.enabled") }}</Label>
            <Switch id="mcp-key-enabled" v-model="keyForm.enabled" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" :disabled="working" @click="keyDialogOpen = false">{{ t("mcpAccess.cancel") }}</Button>
          <Button :disabled="working" data-testid="mcp-save-key" @click="saveKey">
            <Loader2 v-if="working" class="mr-1 h-3.5 w-3.5 animate-spin" />
            {{ editingKey || keyNames.length <= 1 ? t("mcpAccess.save") : t("mcpAccess.createKeysCount", { count: keyNames.length }) }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Issued secrets -->
    <Dialog :open="issued.length > 0" @update:open="(open: boolean) => !open && (issued = [])">
      <DialogContent class="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{{ t("mcpAccess.secretTitle", { count: issued.length }, issued.length) }}</DialogTitle>
          <DialogDescription :class="issuedCopyable ? '' : 'text-amber-700 dark:text-amber-300'">{{ issuedCopyable ? t("mcpAccess.secretStoredHint") : t("mcpAccess.secretWarning") }}</DialogDescription>
        </DialogHeader>
        <div class="grid gap-3 text-xs">
          <div class="flex items-center justify-between gap-2">
            <span class="text-muted-foreground">{{ t("mcpAccess.copyFormat") }}</span>
            <Button size="sm" variant="outline" data-testid="mcp-copy-all" @click="copy(keyLines(issued.map((item) => ({ name: item.key.name, secret: item.secret }))))"> <CopyCheck class="mr-1 h-3.5 w-3.5" />{{ t("mcpAccess.copyAll") }} </Button>
          </div>
          <div class="max-h-72 overflow-y-auto rounded-md border">
            <div v-for="item in issued" :key="item.key.id" class="flex min-w-0 items-center gap-2 border-b px-2 py-1.5 last:border-b-0">
              <span class="w-28 shrink-0 truncate font-medium" :title="item.key.name">{{ item.key.name }}</span>
              <code data-testid="mcp-issued-secret" class="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded bg-muted px-2 py-1">{{ item.secret }}</code>
              <Button variant="ghost" size="icon-xs" :title="t('mcpAccess.copy')" @click="copy(item.secret)"><Copy class="h-3.5 w-3.5" /></Button>
            </div>
          </div>
          <div v-if="issuedSingle" class="grid gap-1">
            <div class="flex items-center justify-between">
              <span class="font-medium">{{ t("mcpAccess.clientConfig") }}</span>
              <Button variant="ghost" size="icon-xs" :title="t('mcpAccess.copy')" @click="copy(issuedConfig)"><Copy class="h-3.5 w-3.5" /></Button>
            </div>
            <pre class="max-h-48 overflow-auto rounded border bg-background p-2 text-[11px]">{{ issuedConfig }}</pre>
          </div>
        </div>
        <DialogFooter>
          <Button @click="issued = []">{{ t("mcpAccess.close") }}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Confirmation -->
    <Dialog :open="Boolean(pending)" @update:open="(open: boolean) => !open && !working && (pending = null)">
      <DialogContent class="max-w-md">
        <DialogHeader>
          <DialogTitle>{{ pendingTitle }}</DialogTitle>
          <DialogDescription>{{ pendingMessage }}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" :disabled="working" @click="pending = null">{{ t("mcpAccess.cancel") }}</Button>
          <Button :variant="pending?.kind === 'rotateKey' ? 'default' : 'destructive'" :disabled="working" @click="confirmPending">
            <Loader2 v-if="working" class="mr-1 h-3.5 w-3.5 animate-spin" />
            {{ pending?.kind === "rotateKey" ? t("mcpAccess.rotate") : t("mcpAccess.delete") }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </section>
</template>

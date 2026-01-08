import Dexie, { type Table } from 'dexie'

export type StoredFile = {
  id?: number
  ownerUserId?: string | null
  name: string
  type: string
  size: number
  data: Blob
  createdAt: number
  groupKey: string
  version: number
}

export type FileMeta = {
  groupKey: string
  ownerUserId?: string | null
  folder: string
  labelsJson: string // string[]
  createdAt: number
  updatedAt: number
}

export type OcrCache = {
  fileId: number
  ownerUserId?: string | null
  text: string
  createdAt: number
  updatedAt: number
}

export type EntityLink = {
  id?: number
  ownerUserId?: string | null
  fromType: 'planning' | 'note'
  fromId: number
  toType: 'fileGroup' | 'note' | 'planning'
  toKey: string // fileGroup => groupKey, otherwise numeric id string
  createdAt: number
}

export type PlanningItem = {
  id?: number
  ownerUserId?: string | null
  workspaceId?: string | null // Added for workspace filtering
  date: string // YYYY-MM-DD
  start: string // HH:mm
  end: string // HH:mm
  title: string
  notes?: string
  priority: 'low' | 'medium' | 'high'
  status: 'todo' | 'in_progress' | 'done'
  tagsJson: string // string[]
  remoteId?: string
  createdAt: number
  updatedAt: number
}

export type NoteDraft = {
  id?: number
  ownerUserId?: string | null
  workspaceId?: string | null // Added for workspace filtering
  subject: string
  body: string // HTML (rich-text)
  attachmentFileIds: number[]
  remoteId?: string
  createdAt: number
  updatedAt: number
}

export type AppErrorLog = {
  id?: number
  createdAt: number
  level: 'error' | 'warn'
  source: 'react' | 'window' | 'unhandledrejection' | 'api' | 'other'
  message: string
  stack?: string
  metaJson: string
}

class AppDB extends Dexie {
  files!: Table<StoredFile, number>
  fileMeta!: Table<FileMeta, string>
  ocr!: Table<OcrCache, number>
  links!: Table<EntityLink, number>
  planning!: Table<PlanningItem, number>
  notes!: Table<NoteDraft, number>
  errors!: Table<AppErrorLog, number>

  constructor() {
    super('stage-planner-db')
    this.version(1).stores({
      files: '++id, createdAt, name, type, size',
      planning: '++id, date, start, end, updatedAt, workspaceId',
      notes: '++id, updatedAt, subject, workspaceId',
    })

    // v2: planning krijgt priority/status
    this.version(2)
      .stores({
        files: '++id, createdAt, name, type, size',
        planning: '++id, date, start, end, updatedAt, priority, status, workspaceId',
        notes: '++id, updatedAt, subject, workspaceId',
      })
      .upgrade(async (tx) => {
        await tx
          .table('planning')
          .toCollection()
          .modify((item: Partial<PlanningItem>) => {
            if (!item.priority) item.priority = 'medium'
            if (!item.status) item.status = 'todo'
          })
      })

    // v3: files -> groupKey/version + meta + ocr + links
    this.version(3)
      .stores({
        files: '++id, createdAt, name, type, size, groupKey, version',
        fileMeta: '&groupKey, updatedAt, folder',
        ocr: '&fileId, updatedAt',
        links: '++id, fromType, fromId, toType, toKey, createdAt',
        planning: '++id, date, start, end, updatedAt, priority, status',
        notes: '++id, updatedAt, subject',
      })
    
    // v4: Add workspaceId to planning and notes for workspace filtering
    this.version(4)
      .stores({
        files: '++id, createdAt, name, type, size, groupKey, version',
        fileMeta: '&groupKey, updatedAt, folder',
        ocr: '&fileId, updatedAt',
        links: '++id, fromType, fromId, toType, toKey, createdAt',
        planning: '++id, date, start, end, updatedAt, priority, status, workspaceId',
        notes: '++id, updatedAt, subject, workspaceId',
      })
      .upgrade(async (_tx) => {
        // workspaceId will be set when items are synced from backend
        // No need to migrate existing items - they'll get workspaceId on next sync
      })
      .upgrade(async (tx) => {
        const filesTable = tx.table('files')
        const metaTable = tx.table('fileMeta')
        const all = await filesTable.toArray()

        // group existing files by groupKey, set incremental versions
        const byKey = new Map<string, Partial<StoredFile>[]>()
        for (const f of all) {
          const file = f as Partial<StoredFile>
          const groupKey = `${file.name}::${file.type || 'application/octet-stream'}`
          file.groupKey = groupKey
          const arr = byKey.get(groupKey) ?? []
          arr.push(file)
          byKey.set(groupKey, arr)
        }

        for (const [key, list] of byKey.entries()) {
          list.sort((a, b) => (a.createdAt ?? 0) - (b.createdAt ?? 0))
          let v = 1
          for (const f of list) {
            f.version = v++
            await filesTable.put(f as StoredFile)
          }
          const now = Date.now()
          await metaTable.put({
            groupKey: key,
            folder: '',
            labelsJson: '[]',
            createdAt: now,
            updatedAt: now,
          })
        }

        // notes: treat existing body as plain text; wrap in <p>
        const notesTable = tx.table('notes')
        await notesTable.toCollection().modify((n: Partial<NoteDraft>) => {
          if (typeof n.body === 'string' && !n.body.trim().startsWith('<')) {
            const escaped = n.body
              .replaceAll('&', '&amp;')
              .replaceAll('<', '&lt;')
              .replaceAll('>', '&gt;')
            n.body = `<p>${escaped.replaceAll('\n', '<br/>')}</p>`
          }
        })
      })

    // v4: planning tags
    this.version(4)
      .stores({
        files: '++id, createdAt, name, type, size, groupKey, version',
        fileMeta: '&groupKey, updatedAt, folder',
        ocr: '&fileId, updatedAt',
        links: '++id, fromType, fromId, toType, toKey, createdAt',
        planning: '++id, date, start, end, updatedAt, priority, status, tagsJson',
        notes: '++id, updatedAt, subject',
      })
      .upgrade(async (tx) => {
        await tx
          .table('planning')
          .toCollection()
          .modify((item: Partial<PlanningItem>) => {
            if (!item.tagsJson) item.tagsJson = '[]'
          })
      })

    // v5: remoteId fields (cloud sync)
    this.version(5)
      .stores({
        files: '++id, createdAt, name, type, size, groupKey, version',
        fileMeta: '&groupKey, updatedAt, folder',
        ocr: '&fileId, updatedAt',
        links: '++id, fromType, fromId, toType, toKey, createdAt',
        planning: '++id, date, start, end, updatedAt, priority, status, tagsJson, remoteId',
        notes: '++id, updatedAt, subject, remoteId',
      })
      .upgrade(async (tx) => {
        // defaults: nothing required
        await tx.table('planning').toCollection().modify((it: Partial<PlanningItem>) => {
          if (it.remoteId === undefined) it.remoteId = undefined
        })
        await tx.table('notes').toCollection().modify((it: Partial<NoteDraft>) => {
          if (it.remoteId === undefined) it.remoteId = undefined
        })
      })

    // v6: error logs
    this.version(6).stores({
      files: '++id, createdAt, name, type, size, groupKey, version',
      fileMeta: '&groupKey, updatedAt, folder',
      ocr: '&fileId, updatedAt',
      links: '++id, fromType, fromId, toType, toKey, createdAt',
      planning: '++id, date, start, end, updatedAt, priority, status, tagsJson, remoteId',
      notes: '++id, updatedAt, subject, remoteId',
      errors: '++id, createdAt, level, source',
    })

    // v7: per-user local planning
    this.version(7)
      .stores({
        files: '++id, createdAt, name, type, size, groupKey, version',
        fileMeta: '&groupKey, updatedAt, folder',
        ocr: '&fileId, updatedAt',
        links: '++id, fromType, fromId, toType, toKey, createdAt',
        planning: '++id, ownerUserId, date, start, end, updatedAt, priority, status, tagsJson, remoteId, [ownerUserId+date]',
        notes: '++id, updatedAt, subject, remoteId',
        errors: '++id, createdAt, level, source',
      })
      .upgrade(async (tx) => {
        // Mark existing items as legacy/unassigned. We'll claim them on first login.
        await tx
          .table('planning')
          .toCollection()
          .modify((it: Partial<PlanningItem>) => {
            if (it.ownerUserId === undefined) it.ownerUserId = null
          })
      })

    // v8: per-user local files + note drafts + links/ocr
    this.version(8)
      .stores({
        files:
          '++id, ownerUserId, createdAt, name, type, size, groupKey, version, [ownerUserId+createdAt], [ownerUserId+groupKey]',
        fileMeta: '&groupKey, ownerUserId, updatedAt, folder',
        ocr: '&fileId, ownerUserId, updatedAt, [ownerUserId+fileId]',
        links: '++id, ownerUserId, fromType, fromId, toType, toKey, createdAt, [ownerUserId+fromId]',
        planning: '++id, ownerUserId, date, start, end, updatedAt, priority, status, tagsJson, remoteId, [ownerUserId+date]',
        notes: '++id, ownerUserId, updatedAt, subject, remoteId',
        errors: '++id, createdAt, level, source',
      })
      .upgrade(async (tx) => {
        const markNull = async (table: string, field: string) => {
          await tx
            .table(table)
            .toCollection()
            .modify((it: Record<string, unknown>) => {
              if (it[field] === undefined) it[field] = null
            })
        }
        await markNull('files', 'ownerUserId')
        await markNull('fileMeta', 'ownerUserId')
        await markNull('ocr', 'ownerUserId')
        await markNull('links', 'ownerUserId')
        await markNull('notes', 'ownerUserId')
      })

    // v9: Add workspaceId to planning and notes for workspace filtering
    this.version(9)
      .stores({
        files:
          '++id, ownerUserId, createdAt, name, type, size, groupKey, version, [ownerUserId+createdAt], [ownerUserId+groupKey]',
        fileMeta: '&groupKey, ownerUserId, updatedAt, folder',
        ocr: '&fileId, ownerUserId, updatedAt, [ownerUserId+fileId]',
        links: '++id, ownerUserId, fromType, fromId, toType, toKey, createdAt, [ownerUserId+fromId]',
        planning: '++id, ownerUserId, workspaceId, date, start, end, updatedAt, priority, status, tagsJson, remoteId, [ownerUserId+date], [workspaceId+date]',
        notes: '++id, ownerUserId, workspaceId, updatedAt, subject, remoteId',
        errors: '++id, createdAt, level, source',
      })
      .upgrade(async (_tx) => {
        // workspaceId will be set when items are synced from backend
        // No need to migrate existing items - they'll get workspaceId on next sync
      })
  }
}

export const db = new AppDB()



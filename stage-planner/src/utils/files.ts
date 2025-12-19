import type { StoredFile } from '../db/db'

export type FileCategory =
  | 'images'
  | 'pdf'
  | 'text'
  | 'office-word'
  | 'office-excel'
  | 'office-powerpoint'
  | 'audio'
  | 'video'
  | 'other'

export function fileCategory(f: StoredFile): FileCategory {
  const t = (f.type || '').toLowerCase()
  if (t.startsWith('image/')) return 'images'
  if (t === 'application/pdf') return 'pdf'
  if (t.startsWith('text/')) return 'text'
  if (t === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') return 'office-word'
  if (t === 'application/msword') return 'office-word'
  if (t === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet') return 'office-excel'
  if (t === 'application/vnd.ms-excel') return 'office-excel'
  if (t === 'application/vnd.openxmlformats-officedocument.presentationml.presentation') return 'office-powerpoint'
  if (t === 'application/vnd.ms-powerpoint') return 'office-powerpoint'
  if (t.startsWith('audio/')) return 'audio'
  if (t.startsWith('video/')) return 'video'

  // fallback via extensie
  const name = (f.name || '').toLowerCase()
  if (/\.(png|jpe?g|gif|webp|bmp|svg)$/.test(name)) return 'images'
  if (/\.(pdf)$/.test(name)) return 'pdf'
  if (/\.(txt|md|json|csv|log)$/.test(name)) return 'text'
  if (/\.(docx|doc)$/.test(name)) return 'office-word'
  if (/\.(xlsx|xls)$/.test(name)) return 'office-excel'
  if (/\.(pptx|ppt)$/.test(name)) return 'office-powerpoint'
  if (/\.(mp3|wav|ogg|m4a)$/.test(name)) return 'audio'
  if (/\.(mp4|webm|mov|mkv)$/.test(name)) return 'video'
  return 'other'
}

export function categoryLabel(cat: FileCategory) {
  switch (cat) {
    case 'images':
      return 'Afbeeldingen'
    case 'pdf':
      return 'PDF'
    case 'text':
      return 'Tekst'
    case 'office-word':
      return 'Word'
    case 'office-excel':
      return 'Excel'
    case 'office-powerpoint':
      return 'PowerPoint'
    case 'audio':
      return 'Audio'
    case 'video':
      return 'Video'
    default:
      return 'Overig'
  }
}

export function categoryOrder(cat: FileCategory) {
  return [
    'images',
    'pdf',
    'text',
    'office-word',
    'office-excel',
    'office-powerpoint',
    'audio',
    'video',
    'other',
  ].indexOf(cat)
}

export function formatBytes(bytes: number) {
  const units = ['B', 'KB', 'MB', 'GB']
  let size = bytes
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit++
  }
  return `${size.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}



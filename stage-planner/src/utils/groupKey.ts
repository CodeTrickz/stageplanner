export function makeGroupKey(name: string, type: string, ownerUserId?: string | null) {
  const owner = ownerUserId || '__local__'
  const t = type || 'application/octet-stream'
  // Prefix with "u:" so we can distinguish the new scoped format from legacy keys.
  return `u:${owner}::${name}::${t}`
}

export function parseGroupKey(groupKey: string) {
  // New format: u:<owner>::<name>::<type>
  if (groupKey.startsWith('u:')) {
    const first = groupKey.indexOf('::')
    if (first > 1) {
      const ownerUserId = groupKey.slice(2, first)
      const rest = groupKey.slice(first + 2)
      const idx = rest.lastIndexOf('::')
      if (idx < 0) return { ownerUserId, name: rest, type: '' }
      return { ownerUserId, name: rest.slice(0, idx), type: rest.slice(idx + 2) }
    }
  }
  // Legacy format: <name>::<type>
  const idx = groupKey.lastIndexOf('::')
  if (idx < 0) return { ownerUserId: null as string | null, name: groupKey, type: '' }
  return { ownerUserId: null as string | null, name: groupKey.slice(0, idx), type: groupKey.slice(idx + 2) }
}







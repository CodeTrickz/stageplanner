import { useEffect } from 'react'

type HotkeyHandler = (event: KeyboardEvent) => void

function isTextInputElement(el: HTMLElement | null): boolean {
  if (!el) return false
  const tag = el.tagName.toLowerCase()
  const isEditable =
    tag === 'input' ||
    tag === 'textarea' ||
    tag === 'select' ||
    (el as HTMLElement).isContentEditable

  // Allow hotkeys on inputs that explicitly opt-in via data-allow-hotkeys
  const allowHotkeysAttr = el.getAttribute('data-allow-hotkeys')

  return isEditable && allowHotkeysAttr !== 'true'
}

/**
 * Global hotkeys hook.
 *
 * - Listens on `window` for keydown
 * - Ignores events when the focus is inside an input/textarea/select/contentEditable
 *   (unless the element has `data-allow-hotkeys="true"`)
 * - Cleans up on unmount
 */
export function useGlobalHotkeys(handler: HotkeyHandler, deps: unknown[] = []): void {
  useEffect(() => {
    const listener = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      if (isTextInputElement(target)) return
      handler(event)
    }

    window.addEventListener('keydown', listener)
    return () => {
      window.removeEventListener('keydown', listener)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
}


import DownloadIcon from '@mui/icons-material/Download'
import PsychologyIcon from '@mui/icons-material/Psychology'
import { Alert, Box, Button, Dialog, DialogContent, DialogTitle, Stack, Typography, useMediaQuery, useTheme } from '@mui/material'
import mammoth from 'mammoth'
import DOMPurify from 'dompurify'
import ExcelJS from 'exceljs'
import { useCallback, useEffect, useMemo, useState } from 'react'
import type { StoredFile } from '../db/db'
import { useObjectUrl } from '../hooks/useObjectUrl'
import { fetchFileBlob, fileCategory, formatBytes } from '../utils/files'
import Tesseract from 'tesseract.js'
import { useSettings } from '../app/settings'
import { useApiToken } from '../api/client'
const PDFJS_WORKER_VERSION = '4.8.69'

function escapeHtml(value: unknown) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function worksheetToHtml(worksheet: ExcelJS.Worksheet) {
  const rows: string[] = []
  worksheet.eachRow({ includeEmpty: true }, (row) => {
    const cells: string[] = []
    row.eachCell({ includeEmpty: true }, (cell) => {
      const text = cell.text ?? ''
      cells.push(`<td>${escapeHtml(text)}</td>`)
    })
    rows.push(`<tr>${cells.join('')}</tr>`)
  })
  return `<table>${rows.join('')}</table>`
}

// pdfjs-dist v4.x
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as pdfjsLib from 'pdfjs-dist'

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export function FilePreviewDialog({
  open,
  file,
  onClose,
}: {
  open: boolean
  file: StoredFile | null
  onClose: () => void
}) {
  const token = useApiToken()
  const { autoExtractTextOnOpen, ocrLanguage } = useSettings()
  const theme = useTheme()
  const fullScreen = useMediaQuery(theme.breakpoints.down('sm'))
  const [blob, setBlob] = useState<Blob | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const localBlob = file?.data && file.data.size > 0 ? file.data : null
  const activeBlob = blob ?? localBlob
  const url = useObjectUrl(activeBlob ?? null)
  const cat = useMemo(() => (file ? fileCategory(file) : 'other'), [file])
  const [text, setText] = useState<string | null>(null)
  const [docxHtml, setDocxHtml] = useState<string | null>(null)
  const [xlsxHtml, setXlsxHtml] = useState<string | null>(null)
  const [ocrText, setOcrText] = useState<string | null>(null)
  const [ocrStatus, setOcrStatus] = useState<'idle' | 'loading' | 'done' | 'error'>('idle')
  const safeDocxHtml = useMemo(
    () => (docxHtml ? DOMPurify.sanitize(docxHtml) : '<p>(leeg)</p>'),
    [docxHtml],
  )
  const safeXlsxHtml = useMemo(() => (xlsxHtml ? DOMPurify.sanitize(xlsxHtml) : ''), [xlsxHtml])

  useEffect(() => {
    let cancelled = false
    async function ensureBlob() {
      if (!open || !file) return
      if (localBlob || blob) return
      if (!token || !file.remoteId) {
        setLoadError('Bestand kan niet worden opgehaald (geen server-id of login).')
        return
      }
      try {
        const remoteBlob = await fetchFileBlob(file.remoteId, token)
        if (!cancelled) {
          setBlob(remoteBlob)
          setLoadError(null)
        }
      } catch (e) {
        if (!cancelled) setLoadError(e instanceof Error ? e.message : 'Bestand laden mislukt.')
      }
    }
    setBlob(null)
    setLoadError(null)
    void ensureBlob()
    return () => {
      cancelled = true
    }
  }, [open, file, token, localBlob, blob])

  useEffect(() => {
    let cancelled = false
    async function run() {
      if (!file) return
      if (!activeBlob) return
      try {
        if (cat === 'text') {
          const t = await activeBlob.text()
          if (!cancelled) setText(t)
          return
        }
        if (cat === 'office-word') {
          const buf = await activeBlob.arrayBuffer()
          const res = await mammoth.convertToHtml({ arrayBuffer: buf as ArrayBuffer })
          if (!cancelled) setDocxHtml(res.value || '')
          return
        }
        if (cat === 'office-excel') {
          const buf = await activeBlob.arrayBuffer()
          const workbook = new ExcelJS.Workbook()
          await workbook.xlsx.load(buf)
          const worksheet = workbook.worksheets[0]
          const html = worksheet ? worksheetToHtml(worksheet) : ''
          if (!cancelled) setXlsxHtml(html || '')
          return
        }
      } catch {
        // ignore
      }
    }
    setText(null)
    setDocxHtml(null)
    setXlsxHtml(null)
    void run()
    return () => {
      cancelled = true
    }
  }, [file, cat, activeBlob])

  const runOcr = useCallback(async () => {
    if (!activeBlob) return
    setOcrStatus('loading')
    setOcrText(null)
    try {
      let extracted = ''
      if (cat === 'images') {
        const lang = (ocrLanguage || 'eng').trim() || 'eng'
        const { data } = await Tesseract.recognize(activeBlob, lang)
        extracted = data.text || ''
      } else if (cat === 'pdf') {
        // Extract embedded text (fast). For scanned PDFs OCR is more work; this covers most PDFs.
        const buf = await activeBlob.arrayBuffer()
        // configure worker src for pdfjs
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        ;(pdfjsLib as any).GlobalWorkerOptions.workerSrc = `https://cdn.jsdelivr.net/npm/pdfjs-dist@${PDFJS_WORKER_VERSION}/build/pdf.worker.min.mjs`
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const doc = await (pdfjsLib as any).getDocument({ data: buf }).promise
        let out = ''
        for (let i = 1; i <= doc.numPages; i++) {
          const page = await doc.getPage(i)
          const content = await page.getTextContent()
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const strings = (content.items as any[]).map((it: { str?: string }) => it.str).filter(Boolean) as string[]
          out += strings.join(' ') + '\n'
        }
        extracted = out.trim()
      } else {
        extracted = ''
      }

      setOcrText(extracted)
      setOcrStatus('done')
    } catch (e) {
      setOcrStatus('error')
      setOcrText(e instanceof Error ? e.message : 'ocr_failed')
    }
  }, [cat, ocrLanguage, activeBlob])

  // Auto run OCR/extract on open (only if not cached yet)
  useEffect(() => {
    let cancelled = false
    async function maybeAuto() {
      if (!open) return
      if (!autoExtractTextOnOpen) return
      if (!(cat === 'images' || cat === 'pdf')) return
      if (ocrStatus === 'loading' || ocrStatus === 'done') return
      if (!cancelled) await runOcr()
    }
    void maybeAuto()
    return () => {
      cancelled = true
    }
  }, [open, autoExtractTextOnOpen, file, cat, ocrLanguage, ocrStatus, runOcr])

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md" fullScreen={fullScreen}>
      <DialogTitle sx={{ p: { xs: 1.5, sm: 2 } }}>
        <Stack direction="column" spacing={{ xs: 1, sm: 1.5 }} sx={{ '@media (min-width:600px)': { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' } }}>
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography sx={{ fontWeight: 800, fontSize: { xs: '0.875rem', sm: '1rem' } }} noWrap>
              {file?.name ?? 'Preview'}
            </Typography>
            {file && (
              <Typography variant="body2" color="text.secondary" noWrap sx={{ fontSize: { xs: '0.75rem', sm: '0.8125rem' } }}>
                {file.type || 'onbekend'} • {formatBytes(file.size)} •{' '}
                {new Date(file.createdAt).toLocaleString()}
              </Typography>
            )}
          </Box>
          {file && (
            <Stack direction="row" spacing={1} sx={{ flexShrink: 0 }}>
              {(cat === 'images' || cat === 'pdf') && (
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<PsychologyIcon />}
                  onClick={() => void runOcr()}
                  disabled={ocrStatus === 'loading'}
                  sx={{ fontSize: { xs: '0.75rem', sm: '0.875rem' } }}
                >
                  <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>
                    {cat === 'pdf' ? 'Extract tekst' : 'OCR'}
                  </Box>
                  <Box component="span" sx={{ display: { xs: 'inline', sm: 'none' } }}>
                    {cat === 'pdf' ? 'Extract' : 'OCR'}
                  </Box>
                </Button>
              )}
              <Button
                variant="outlined"
                size="small"
                startIcon={<DownloadIcon />}
                onClick={async () => {
                  if (activeBlob) {
                    downloadBlob(activeBlob, file.name)
                    return
                  }
                  if (!token || !file.remoteId) return
                  try {
                    const remoteBlob = await fetchFileBlob(file.remoteId, token)
                    downloadBlob(remoteBlob, file.name)
                  } catch {
                    // ignore
                  }
                }}
              >
                Download
              </Button>
            </Stack>
          )}
        </Stack>
      </DialogTitle>
      <DialogContent dividers>
        {!file && <Alert severity="info">Geen bestand geselecteerd.</Alert>}
        {loadError && <Alert severity="warning" sx={{ mb: 1 }}>{loadError}</Alert>}

        {file && cat === 'images' && url && (
          <Box
            component="img"
            src={url}
            alt={file.name}
            sx={{ width: '100%', maxHeight: '70vh', objectFit: 'contain', borderRadius: 2 }}
          />
        )}

        {file && cat === 'pdf' && url && (
          <Box
            component="iframe"
            src={url}
            title={file.name}
            sx={{ width: '100%', height: '70vh', border: 0, borderRadius: 2 }}
          />
        )}

        {file && (cat === 'audio' || cat === 'video') && url && (
          <Box sx={{ width: '100%' }}>
            {cat === 'audio' ? (
              <audio controls style={{ width: '100%' }} src={url} />
            ) : (
              <video controls style={{ width: '100%', maxHeight: '70vh' }} src={url} />
            )}
          </Box>
        )}

        {file && cat === 'text' && (
          <Box sx={{ whiteSpace: 'pre-wrap', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace' }}>
            {text == null ? (
              <Alert severity="info">Tekst preview laden…</Alert>
            ) : (
              <Typography component="div" sx={{ whiteSpace: 'pre-wrap' }}>
                {text.length > 50000 ? text.slice(0, 50000) + '\n\n… (afgekapt)' : text}
              </Typography>
            )}
          </Box>
        )}

        {file && cat === 'office-word' && (
          <Box>
            {docxHtml == null ? (
              <Alert severity="info">Word preview laden…</Alert>
            ) : (
              <Box
                sx={{
                  '& img': { maxWidth: '100%' },
                  '& table': { borderCollapse: 'collapse', width: '100%' },
                  '& td, & th': { border: '1px solid', borderColor: 'divider', p: 0.75 },
                }}
                dangerouslySetInnerHTML={{ __html: safeDocxHtml }}
              />
            )}
          </Box>
        )}

        {file && cat === 'office-excel' && (
          <Box>
            {xlsxHtml == null ? (
              <Alert severity="info">Excel preview laden…</Alert>
            ) : xlsxHtml ? (
              <Box
                sx={{
                  overflowX: 'auto',
                  '& table': { borderCollapse: 'collapse', width: 'max-content', minWidth: '100%' },
                  '& td, & th': { border: '1px solid', borderColor: 'divider', p: 0.75, whiteSpace: 'nowrap' },
                }}
                dangerouslySetInnerHTML={{ __html: safeXlsxHtml }}
              />
            ) : (
              <Alert severity="info">Geen sheet gevonden.</Alert>
            )}
          </Box>
        )}

        {file && cat === 'office-powerpoint' && (
          <Alert severity="info">
            PowerPoint preview is niet standaard mogelijk in de browser zonder extra (zware) viewer. Download om te openen.
          </Alert>
        )}

        {file && cat === 'other' && (
          <Alert severity="info">
            Geen ingebouwde preview voor dit datatype. Je kan wel downloaden.
          </Alert>
        )}

        {file && (cat === 'images' || cat === 'pdf') && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 900, mb: 1 }}>
              Tekst (OCR/Extract)
            </Typography>
            {ocrStatus === 'idle' && <Alert severity="info">Klik op {cat === 'pdf' ? 'Extract tekst' : 'OCR'}.</Alert>}
            {ocrStatus === 'loading' && <Alert severity="info">Bezig…</Alert>}
            {ocrStatus === 'done' && (
              <Box sx={{ whiteSpace: 'pre-wrap' }}>
                {ocrText?.trim() ? (
                  <Typography component="div" sx={{ whiteSpace: 'pre-wrap' }}>
                    {ocrText}
                  </Typography>
                ) : (
                  <Alert severity="warning">Geen tekst gevonden.</Alert>
                )}
              </Box>
            )}
            {ocrStatus === 'error' && <Alert severity="error">{ocrText ?? 'ocr_failed'}</Alert>}
          </Box>
        )}
      </DialogContent>
    </Dialog>
  )
}



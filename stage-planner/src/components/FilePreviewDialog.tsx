import DownloadIcon from '@mui/icons-material/Download'
import PsychologyIcon from '@mui/icons-material/Psychology'
import { Alert, Box, Button, Dialog, DialogContent, DialogTitle, Stack, Typography } from '@mui/material'
import mammoth from 'mammoth'
import { useEffect, useMemo, useState } from 'react'
import * as XLSX from 'xlsx'
import type { StoredFile } from '../db/db'
import { useObjectUrl } from '../hooks/useObjectUrl'
import { fileCategory, formatBytes } from '../utils/files'
import { db } from '../db/db'
import Tesseract from 'tesseract.js'
import { useSettings } from '../app/settings'
// pdfjs-dist v3.x
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
  const { autoExtractTextOnOpen, ocrLanguage } = useSettings()
  const url = useObjectUrl(file?.data ?? null)
  const cat = useMemo(() => (file ? fileCategory(file) : 'other'), [file])
  const [text, setText] = useState<string | null>(null)
  const [docxHtml, setDocxHtml] = useState<string | null>(null)
  const [xlsxHtml, setXlsxHtml] = useState<string | null>(null)
  const [ocrText, setOcrText] = useState<string | null>(null)
  const [ocrStatus, setOcrStatus] = useState<'idle' | 'loading' | 'done' | 'error'>('idle')

  useEffect(() => {
    let cancelled = false
    async function run() {
      if (!file) return
      try {
        if (cat === 'text') {
          const t = await file.data.text()
          if (!cancelled) setText(t)
          return
        }
        if (cat === 'office-word') {
          const buf = await file.data.arrayBuffer()
          const res = await mammoth.convertToHtml({ arrayBuffer: buf as ArrayBuffer })
          if (!cancelled) setDocxHtml(res.value || '')
          return
        }
        if (cat === 'office-excel') {
          const buf = await file.data.arrayBuffer()
          const wb = XLSX.read(buf, { type: 'array' })
          const sheetName = wb.SheetNames[0]
          const ws = sheetName ? wb.Sheets[sheetName] : undefined
          const html = ws ? XLSX.utils.sheet_to_html(ws) : ''
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
  }, [file, cat])

  useEffect(() => {
    let cancelled = false
    async function loadCached() {
      setOcrText(null)
      setOcrStatus('idle')
      if (!file?.id) return
      const owner = (file as any)?.ownerUserId || '__local__'
      const cached = await db.ocr.where('[ownerUserId+fileId]').equals([owner, file.id] as any).first()
      if (!cached) return
      if (!cancelled) {
        setOcrText(cached.text)
        setOcrStatus('done')
      }
    }
    void loadCached()
    return () => {
      cancelled = true
    }
  }, [file?.id])

  async function runOcr() {
    if (!file?.id) return
    setOcrStatus('loading')
    setOcrText(null)
    try {
      let extracted = ''
      if (cat === 'images') {
        const lang = (ocrLanguage || 'eng').trim() || 'eng'
        const { data } = await Tesseract.recognize(file.data, lang)
        extracted = data.text || ''
      } else if (cat === 'pdf') {
        // Extract embedded text (fast). For scanned PDFs OCR is more work; this covers most PDFs.
        const buf = await file.data.arrayBuffer()
        // configure worker src for pdfjs
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        pdfjsLib.GlobalWorkerOptions.workerSrc = `https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js`
        // eslint-disable-next-line @typescript-eslint/no-unsafe-call
        const doc = await pdfjsLib.getDocument({ data: buf }).promise
        let out = ''
        for (let i = 1; i <= doc.numPages; i++) {
          const page = await doc.getPage(i)
          const content = await page.getTextContent()
          const strings = content.items.map((it: any) => it.str).filter(Boolean)
          out += strings.join(' ') + '\n'
        }
        extracted = out.trim()
      } else {
        extracted = ''
      }

      const now = Date.now()
      const owner = (file as any)?.ownerUserId || '__local__'
      await db.ocr.put({ ownerUserId: owner, fileId: file.id, text: extracted, createdAt: now, updatedAt: now } as any)
      setOcrText(extracted)
      setOcrStatus('done')
    } catch (e) {
      setOcrStatus('error')
      setOcrText(e instanceof Error ? e.message : 'ocr_failed')
    }
  }

  // Auto run OCR/extract on open (only if not cached yet)
  useEffect(() => {
    let cancelled = false
    async function maybeAuto() {
      if (!open) return
      if (!autoExtractTextOnOpen) return
      if (!file?.id) return
      if (!(cat === 'images' || cat === 'pdf')) return
      if (ocrStatus === 'loading' || ocrStatus === 'done') return
      const owner = (file as any)?.ownerUserId || '__local__'
      const cached = await db.ocr.where('[ownerUserId+fileId]').equals([owner, file.id] as any).first()
      if (cached) return
      if (!cancelled) await runOcr()
    }
    void maybeAuto()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, autoExtractTextOnOpen, file?.id, cat, ocrLanguage])

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>
        <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
          <Box sx={{ minWidth: 0 }}>
            <Typography sx={{ fontWeight: 800 }} noWrap>
              {file?.name ?? 'Preview'}
            </Typography>
            {file && (
              <Typography variant="body2" color="text.secondary" noWrap>
                {file.type || 'onbekend'} • {formatBytes(file.size)} •{' '}
                {new Date(file.createdAt).toLocaleString()}
              </Typography>
            )}
          </Box>
          {file && (
            <Stack direction="row" spacing={1}>
              {(cat === 'images' || cat === 'pdf') && (
                <Button
                  variant="outlined"
                  startIcon={<PsychologyIcon />}
                  onClick={() => void runOcr()}
                  disabled={ocrStatus === 'loading'}
                >
                  {cat === 'pdf' ? 'Extract tekst' : 'OCR'}
                </Button>
              )}
              <Button
                variant="outlined"
                startIcon={<DownloadIcon />}
                onClick={() => downloadBlob(file.data, file.name)}
              >
                Download
              </Button>
            </Stack>
          )}
        </Stack>
      </DialogTitle>
      <DialogContent dividers>
        {!file && <Alert severity="info">Geen bestand geselecteerd.</Alert>}

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
                dangerouslySetInnerHTML={{ __html: docxHtml || '<p>(leeg)</p>' }}
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
                dangerouslySetInnerHTML={{ __html: xlsxHtml }}
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



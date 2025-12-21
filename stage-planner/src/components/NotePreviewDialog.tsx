import DownloadIcon from '@mui/icons-material/Download'
import { Alert, Box, Button, Dialog, DialogContent, DialogTitle, Divider, Stack, Typography, useMediaQuery, useTheme } from '@mui/material'
import type { NoteDraft, StoredFile } from '../db/db'

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

export function NotePreviewDialog({
  open,
  note,
  files,
  onClose,
}: {
  open: boolean
  note: NoteDraft | null
  files: StoredFile[]
  onClose: () => void
}) {
  const theme = useTheme()
  const fullScreen = useMediaQuery(theme.breakpoints.down('sm'))
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md" fullScreen={fullScreen}>
      <DialogTitle>
        <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
          <Box sx={{ minWidth: 0 }}>
            <Typography sx={{ fontWeight: 900 }} noWrap>
              Preview: {note?.subject?.trim() ? note.subject : '(zonder onderwerp)'}
            </Typography>
            {note && (
              <Typography variant="body2" color="text.secondary" noWrap>
                Laatst aangepast: {new Date(note.updatedAt).toLocaleString()}
              </Typography>
            )}
          </Box>
        </Stack>
      </DialogTitle>

      <DialogContent dividers>
        {!note && <Alert severity="info">Geen notitie geselecteerd.</Alert>}

        {note && (
          <Box>
            <Box
              sx={{
                '& img': { maxWidth: '100%' },
                '& table': { borderCollapse: 'collapse', width: '100%' },
                '& td, & th': { border: '1px solid', borderColor: 'divider', p: 0.75 },
                '& ul[data-type=\"taskList\"]': { listStyle: 'none', paddingLeft: 0 },
              }}
              // Let op: dit rendert HTML. In deze stage-app is dat oké, maar in production wil je sanitizen.
              dangerouslySetInnerHTML={{ __html: note.body || '<p>(leeg)</p>' }}
            />

            <Divider sx={{ my: 2 }} />

            <Typography variant="subtitle2" sx={{ fontWeight: 900, mb: 1 }}>
              Bijlages
            </Typography>
            {files.length === 0 ? (
              <Alert severity="info">(geen)</Alert>
            ) : (
              <Stack spacing={1}>
                {files.map((f) => (
                  <Stack
                    key={f.id}
                    direction="row"
                    spacing={2}
                    alignItems="center"
                    justifyContent="space-between"
                  >
                    <Typography noWrap sx={{ flex: 1, minWidth: 0 }}>
                      {f.name}
                    </Typography>
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<DownloadIcon />}
                      onClick={() => downloadBlob(f.data, f.name)}
                    >
                      Download
                    </Button>
                  </Stack>
                ))}
              </Stack>
            )}
          </Box>
        )}
      </DialogContent>
    </Dialog>
  )
}










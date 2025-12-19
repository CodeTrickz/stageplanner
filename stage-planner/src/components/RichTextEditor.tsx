import FormatBoldIcon from '@mui/icons-material/FormatBold'
import FormatItalicIcon from '@mui/icons-material/FormatItalic'
import FormatListBulletedIcon from '@mui/icons-material/FormatListBulleted'
import FormatListNumberedIcon from '@mui/icons-material/FormatListNumbered'
import CheckBoxIcon from '@mui/icons-material/CheckBox'
import { Box, IconButton, Paper, Stack } from '@mui/material'
import { EditorContent, useEditor } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'
import TaskItem from '@tiptap/extension-task-item'
import TaskList from '@tiptap/extension-task-list'
import { useEffect } from 'react'

export function RichTextEditor({
  value,
  onChange,
}: {
  value: string
  onChange: (html: string) => void
}) {
  const editor = useEditor({
    extensions: [
      StarterKit,
      TaskList,
      TaskItem.configure({
        nested: true,
      }),
    ],
    content: value || '<p></p>',
    onUpdate: ({ editor }) => {
      onChange(editor.getHTML())
    },
  })

  // keep editor in sync when switching notes
  useEffect(() => {
    if (!editor) return
    const current = editor.getHTML()
    if (current !== value) editor.commands.setContent(value || '<p></p>', { emitUpdate: false })
  }, [editor, value])

  if (!editor) return null

  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
        <IconButton
          size="small"
          onClick={() => editor.chain().focus().toggleBold().run()}
          color={editor.isActive('bold') ? 'primary' : 'default'}
        >
          <FormatBoldIcon fontSize="small" />
        </IconButton>
        <IconButton
          size="small"
          onClick={() => editor.chain().focus().toggleItalic().run()}
          color={editor.isActive('italic') ? 'primary' : 'default'}
        >
          <FormatItalicIcon fontSize="small" />
        </IconButton>
        <IconButton
          size="small"
          onClick={() => editor.chain().focus().toggleBulletList().run()}
          color={editor.isActive('bulletList') ? 'primary' : 'default'}
        >
          <FormatListBulletedIcon fontSize="small" />
        </IconButton>
        <IconButton
          size="small"
          onClick={() => editor.chain().focus().toggleOrderedList().run()}
          color={editor.isActive('orderedList') ? 'primary' : 'default'}
        >
          <FormatListNumberedIcon fontSize="small" />
        </IconButton>
        <IconButton
          size="small"
          onClick={() => editor.chain().focus().toggleTaskList().run()}
          color={editor.isActive('taskList') ? 'primary' : 'default'}
        >
          <CheckBoxIcon fontSize="small" />
        </IconButton>
      </Stack>

      <Box
        sx={{
          '& .ProseMirror': {
            minHeight: 220,
            outline: 'none',
            padding: 1,
          },
          '& .ProseMirror ul[data-type="taskList"]': {
            paddingLeft: 0,
          },
          '& .ProseMirror li[data-type="taskItem"]': {
            display: 'flex',
            gap: 1,
            alignItems: 'flex-start',
          },
          '& .ProseMirror li[data-type="taskItem"] > label': {
            marginTop: '2px',
          },
          '& .ProseMirror li[data-type="taskItem"] > div': {
            flex: 1,
          },
        }}
      >
        <EditorContent editor={editor} />
      </Box>
    </Paper>
  )
}



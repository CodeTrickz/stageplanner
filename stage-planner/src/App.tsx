import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './app/AppShell'
import { RequireAuth } from './auth/RequireAuth'
import { LoginPage } from './pages/LoginPage'
import { VerifyPage } from './pages/VerifyPage'
import { AdminPage } from './pages/AdminPage'
import { DashboardPage } from './pages/DashboardPage'
import { FilesPage } from './pages/FilesPage'
import { NotesPage } from './pages/NotesPage'
import { PlanningPage } from './pages/PlanningPage'
import { TasksOverviewPage } from './pages/TasksOverviewPage'
import { WeekPage } from './pages/WeekPage'
import { SharedPage } from './pages/SharedPage'
import { SettingsPage } from './pages/SettingsPage'

export default function App() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/verify" element={<VerifyPage />} />

        <Route element={<RequireAuth />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/planning" element={<PlanningPage />} />
          <Route path="/week" element={<WeekPage />} />
          <Route path="/taken" element={<TasksOverviewPage />} />
          <Route path="/shared" element={<SharedPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/bestanden" element={<FilesPage />} />
          <Route path="/notities" element={<NotesPage />} />
          <Route path="/admin" element={<AdminPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AppShell>
  )
}

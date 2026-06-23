import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { applyTheme, getInitialTheme } from './hooks/useTheme'

// Apply the persisted/system theme before first paint to avoid a flash of the
// wrong palette.
applyTheme(getInitialTheme())

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

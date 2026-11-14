import { useEffect, useState } from 'react'
import {
  Apple, Settings, Folder, ShieldCheck, Camera, Image,
  Music, CalendarDays, Clock, Wifi, BatteryFull, Search,
  Smartphone, Power, RefreshCw, ChevronRight, Bluetooth,
  Monitor, Lock, Bell, Code2, Home, ArrowLeft,
  Terminal
} from 'lucide-react'

const DEVICE_ID = '69974d1d-6197-40ea-bf72-cd39b35f6476'
const API = 'http://127.0.0.1:8001'

type SettingsData = {
  wifi?: { enabled: boolean; network: string | null }
  bluetooth?: { enabled: boolean }
  display?: { brightness: number; dark_mode: boolean; auto_brightness: boolean }
  battery?: { level: number; charging: boolean }
  privacy?: { location: boolean; camera: boolean; microphone: boolean }
  developer?: { developer_mode: boolean; debug_logging: boolean }
  notifications?: { enabled: boolean }
}

const apps = [
  { name: 'Settings', icon: Settings, color: 'bg-gray-500', page: 'Settings' },
  { name: 'Files', icon: Folder, color: 'bg-blue-500', page: 'Files' },
  { name: 'IPA Lab', icon: ShieldCheck, color: 'bg-emerald-600', page: 'IPA Analyzer' },
  { name: 'Photos', icon: Image, color: 'bg-fuchsia-500', page: 'Photos' },
  { name: 'Camera', icon: Camera, color: 'bg-zinc-700', page: 'Camera' },
  { name: 'Music', icon: Music, color: 'bg-pink-600', page: 'Music' },
  { name: 'Calendar', icon: CalendarDays, color: 'bg-red-500', page: 'Calendar' },
  { name: 'Clock', icon: Clock, color: 'bg-slate-600', page: 'Clock' },
]

function App() {
  const [page, setPage] = useState('Home')
  const [settings, setSettings] = useState<SettingsData>({})
  const [deviceStatus, setDeviceStatus] = useState('running')
  const [filesystem, setFilesystem] = useState<string[]>([])
  const [apiStatus, setApiStatus] = useState('Connecting')
  const [busy, setBusy] = useState(false)

  async function loadSettings() {
    try {
      const response = await fetch(`${API}/api/devices/${DEVICE_ID}/settings`)
      if (!response.ok) throw new Error('API error')
      setSettings(await response.json())
      setApiStatus('Connected')
    } catch {
      setApiStatus('Offline')
    }
  }

  async function loadFilesystem(path = '') {
    try {
      const response = await fetch(
        `${API}/api/devices/${DEVICE_ID}/filesystem?path=${encodeURIComponent(path)}`
      )
      const data = await response.json()
      setFilesystem(data.entries || [])
    } catch {
      setFilesystem([])
    }
  }

  useEffect(() => {
    loadSettings()
    loadFilesystem()
  }, [])

  async function updateSetting(section: string, key: string, value: boolean | number) {
    const updated = {
      ...settings,
      [section]: {
        ...(settings[section as keyof SettingsData] || {}),
        [key]: value
      }
    }
    setSettings(updated)
    try {
      await fetch(`${API}/api/devices/${DEVICE_ID}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [section]: { [key]: value } })
      })
    } catch {
      setApiStatus('Offline')
    }
  }

  async function deviceAction(action: string) {
    setBusy(true)
    try {
      const response = await fetch(`${API}/api/devices/${DEVICE_ID}/${action}`, {
        method: 'POST'
      })
      const data = await response.json()
      setDeviceStatus(data.device?.status || 'running')
    } catch {
      setApiStatus('Offline')
    }
    setBusy(false)
  }

  const Toggle = ({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) => (
    <button onClick={() => onChange(!value)}
      className={`w-11 h-6 rounded-full p-1 transition ${value ? 'bg-emerald-500' : 'bg-gray-600'}`}>
      <span className={`block w-4 h-4 rounded-full bg-white transition ${value ? 'translate-x-5' : ''}`} />
    </button>
  )

  const settingRow = (title: string, subtitle: string, section: string, key: string, value: boolean, Icon: typeof Wifi) => (
    <div className="flex items-center justify-between py-4 border-b border-white/10">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-xl bg-white/10"><Icon size={18}/></div>
        <div><div className="text-sm font-medium">{title}</div><div className="text-xs text-gray-500">{subtitle}</div></div>
      </div>
      <Toggle value={value} onChange={v => updateSetting(section, key, v)}/>
    </div>
  )

  const openApp = (name: string) => {
    setPage(name)
    if (name === 'Files') loadFilesystem()
    if (name === 'Settings') loadSettings()
  }

  return (
    <div className="min-h-screen p-5 lg:p-8">
      <header className="flex flex-wrap items-center justify-between gap-4 mb-8">
        <div className="flex items-center gap-3">
          <div className="w-11 h-11 rounded-2xl bg-blue-600 flex items-center justify-center">
            <Apple size={25}/>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wide">IVSL <span className="text-blue-400">LAB</span></h1>
            <p className="text-xs text-gray-500">iOS Virtual Security Lab</p>
          </div>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className={`px-3 py-2 rounded-full border ${apiStatus === 'Connected' ? 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10' : 'border-amber-500/30 text-amber-400 bg-amber-500/10'}`}>
            ● API {apiStatus}
          </span>
          <span className="px-3 py-2 rounded-full bg-white/5 border border-white/10 text-gray-400">BUILD 0.1.0</span>
        </div>
      </header>

      <main className="grid grid-cols-1 xl:grid-cols-[260px_minmax(360px,1fr)_300px] gap-8 max-w-[1500px] mx-auto">
        <aside className="space-y-6">
          <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
            <p className="text-xs uppercase tracking-widest text-gray-500 mb-4">Workspace</p>
            {[
              ['Overview', Home], ['Device', Smartphone], ['Filesystem', Folder],
              ['IPA Analyzer', ShieldCheck], ['Developer Tools', Terminal]
            ].map(([name, Icon]: any) => (
              <button key={name} onClick={() => openApp(name === 'Overview' ? 'Home' : name === 'Device' ? 'Home' : name)}
                className={`w-full flex items-center gap-3 p-3 rounded-xl text-sm mb-1 ${page === name || (name === 'Overview' && page === 'Home') ? 'bg-blue-600/20 text-blue-300' : 'text-gray-400 hover:bg-white/5'}`}>
                <Icon size={17}/>{name}
              </button>
            ))}
          </section>

          <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
            <p className="text-xs uppercase tracking-widest text-gray-500 mb-4">Selected device</p>
            <div className="flex gap-3 items-center">
              <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-gray-500 to-gray-800 flex items-center justify-center">
                <Smartphone size={25}/>
              </div>
              <div><p className="font-semibold text-sm">iPhone 16 Pro</p><p className="text-xs text-gray-500">iOS 18.0 profile</p></div>
            </div>
            <div className="mt-4 space-y-2 text-xs text-gray-400">
              <div className="flex justify-between"><span>Architecture</span><span>ARM64</span></div>
              <div className="flex justify-between"><span>Memory</span><span>8 GB</span></div>
              <div className="flex justify-between"><span>Storage</span><span>256 GB</span></div>
              <div className="flex justify-between"><span>Runtime</span><span>Simulated</span></div>
            </div>
          </section>
        </aside>

        <section className="flex flex-col items-center">
          <div className="w-full flex items-center justify-between mb-5">
            <div><h2 className="text-lg font-semibold">Virtual Device</h2><p className="text-xs text-gray-500">Interactive device preview</p></div>
            <span className="text-xs text-emerald-400">● {deviceStatus}</span>
          </div>

          <div className="phone-frame rounded-[3rem] p-2 w-[310px] max-w-full bg-black">
            <div className="phone-wallpaper rounded-[2.45rem] min-h-[610px] overflow-hidden relative">
              <div className="flex justify-between px-7 pt-4 text-xs font-semibold">
                <span>9:41</span>
                <div className="flex gap-1.5 items-center"><Wifi size={14}/><BatteryFull size={17}/></div>
              </div>
              <div className="flex justify-center mt-2"><div className="w-24 h-6 rounded-full bg-black"/></div>

              {page === 'Home' ? (
                <>
                  <div className="text-center mt-9 mb-8">
                    <p className="text-sm text-white/70">Friday, November 13</p>
                    <p className="text-6xl font-light tracking-tight mt-1">9:41</p>
                  </div>
                  <div className="grid grid-cols-4 gap-x-3 gap-y-7 px-4">
                    {apps.map(app => (
                      <button key={app.name} onClick={() => openApp(app.page)} className="flex flex-col items-center gap-2">
                        <div className={`${app.color} w-12 h-12 rounded-[15px] flex items-center justify-center shadow-lg`}>
                          <app.icon size={25}/>
                        </div>
                        <span className="text-[10px]">{app.name}</span>
                      </button>
                    ))}
                  </div>
                  <div className="absolute bottom-5 left-4 right-4 glass rounded-3xl p-3 flex justify-around">
                    {[PhoneIcon, Search, Settings, Camera].map((Icon, i) => (
                      <button key={i} onClick={() => i === 2 ? openApp('Settings') : openApp('Home')} className="p-2"><Icon size={23}/></button>
                    ))}
                  </div>
                </>
              ) : page === 'Settings' ? (
                <div className="px-4 pt-5 pb-5">
                  <button onClick={() => setPage('Home')} className="flex items-center gap-1 text-xs text-blue-300 mb-4"><ArrowLeft size={14}/> Home</button>
                  <h2 className="text-2xl font-bold mb-4">Settings</h2>
                  <div className="rounded-2xl bg-white/10 p-3 mb-3 flex items-center gap-3">
                    <div className="w-10 h-10 rounded-full bg-gray-400 flex items-center justify-center"><Smartphone/></div>
                    <div><p className="font-semibold text-sm">My Virtual iPhone</p><p className="text-xs text-white/50">iPhone 16 Pro · iOS 18.0</p></div>
                  </div>
                  <div className="max-h-[400px] overflow-y-auto pr-1">
                    {settingRow('Wi-Fi', 'Wireless networking', 'wifi', 'enabled', settings.wifi?.enabled ?? true, Wifi)}
                    {settingRow('Bluetooth', 'Nearby devices', 'bluetooth', 'enabled', settings.bluetooth?.enabled ?? true, Bluetooth)}
                    {settingRow('Dark Mode', 'Display appearance', 'display', 'dark_mode', settings.display?.dark_mode ?? false, Monitor)}
                    {settingRow('Location', 'Location services', 'privacy', 'location', settings.privacy?.location ?? true, Lock)}
                    {settingRow('Camera', 'Camera permission', 'privacy', 'camera', settings.privacy?.camera ?? true, Camera)}
                    {settingRow('Microphone', 'Microphone permission', 'privacy', 'microphone', settings.privacy?.microphone ?? true, Bell)}
                    {settingRow('Developer Mode', 'Developer features', 'developer', 'developer_mode', settings.developer?.developer_mode ?? false, Code2)}
                    {settingRow('Notifications', 'App notifications', 'notifications', 'enabled', settings.notifications?.enabled ?? true, Bell)}
                  </div>
                </div>
              ) : page === 'Files' || page === 'Filesystem' ? (
                <div className="px-4 pt-5">
                  <button onClick={() => setPage('Home')} className="flex items-center gap-1 text-xs text-blue-300 mb-4"><ArrowLeft size={14}/> Home</button>
                  <h2 className="text-2xl font-bold mb-2">Files</h2>
                  <p className="text-xs text-white/50 mb-4">Virtual device directories</p>
                  <div className="space-y-2">
                    {filesystem.map((entry: any) => (
                      <div key={entry.name} className="flex gap-3 items-center bg-white/10 rounded-xl p-3 text-sm">
                        <Folder size={19} className="text-blue-300"/>{entry.name}<span className="ml-auto text-xs text-white/40">Folder</span>
                      </div>
                    ))}
                    {filesystem.length === 0 && <p className="text-xs text-white/50">No directory data available.</p>}
                  </div>
                </div>
              ) : (
                <div className="px-5 pt-8">
                  <button onClick={() => setPage('Home')} className="flex items-center gap-1 text-xs text-blue-300 mb-6"><ArrowLeft size={14}/> Home</button>
                  <div className="w-14 h-14 rounded-2xl bg-emerald-600 flex items-center justify-center mb-4"><ShieldCheck size={30}/></div>
                  <h2 className="text-2xl font-bold">{page}</h2>
                  <p className="text-xs text-white/60 mt-2">IVSL module</p>
                  <div className="glass rounded-2xl p-4 mt-6">
                    <p className="text-sm font-semibold">Module initialized</p>
                    <p className="text-xs text-white/60 mt-2">This module will be connected to its backend functionality in the next development milestone.</p>
                  </div>
                </div>
              )}
              <div className="absolute bottom-1 left-1/2 -translate-x-1/2 w-28 h-1 rounded-full bg-white/80"/>
            </div>
          </div>
          <div className="flex gap-3 mt-6">
            <button disabled={busy} onClick={() => deviceAction('boot')} className="px-4 py-2 rounded-xl bg-emerald-600/20 border border-emerald-500/30 text-emerald-300 text-xs flex gap-2 items-center"><Power size={14}/> Boot</button>
            <button disabled={busy} onClick={() => deviceAction('restart')} className="px-4 py-2 rounded-xl bg-blue-600/20 border border-blue-500/30 text-blue-300 text-xs flex gap-2 items-center"><RefreshCw size={14}/> Restart</button>
            <button disabled={busy} onClick={() => deviceAction('shutdown')} className="px-4 py-2 rounded-xl bg-red-600/20 border border-red-500/30 text-red-300 text-xs flex gap-2 items-center"><Power size={14}/> Shutdown</button>
          </div>
        </section>

        <aside className="space-y-5">
          <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
            <h3 className="font-semibold mb-4">Device information</h3>
            <div className="space-y-4 text-sm">
              {[
                ['Device model', 'iPhone 16 Pro'],
                ['iOS profile', '18.0'],
                ['Hardware ID', 'iPhone17,1'],
                ['Architecture', 'arm64'],
                ['RAM', '8 GB'],
                ['Storage', '256 GB']
              ].map(([a,b]) => <div key={a} className="flex justify-between gap-3"><span className="text-gray-500">{a}</span><span className="text-gray-200">{b}</span></div>)}
            </div>
          </section>
          <section className="rounded-2xl border border-white/10 bg-white/[0.03] p-5">
            <h3 className="font-semibold mb-3">Quick modules</h3>
            {[
              [ShieldCheck, 'IPA Security Analyzer', 'Static analysis only'],
              [Folder, 'Virtual Filesystem', 'Browse simulated files'],
              [Code2, 'Developer Tools', 'Runtime profile and settings']
            ].map(([Icon, title, desc]: any) => (
              <button key={title} onClick={() => openApp(title === 'Virtual Filesystem' ? 'Files' : title === 'Developer Tools' ? 'Developer Tools' : 'IPA Analyzer')} className="w-full flex items-center gap-3 py-3 border-b border-white/10 text-left">
                <div className="p-2 rounded-xl bg-blue-500/15 text-blue-300"><Icon size={19}/></div>
                <div className="flex-1"><p className="text-sm">{title}</p><p className="text-xs text-gray-500">{desc}</p></div>
                <ChevronRight size={16} className="text-gray-500"/>
              </button>
            ))}
          </section>
          <section className="rounded-2xl border border-blue-500/20 bg-blue-500/[0.06] p-4">
            <p className="text-xs text-blue-300 font-semibold">LAB NOTICE</p>
            <p className="text-xs text-gray-400 mt-2 leading-relaxed">IVSL currently uses a simulated iOS environment on Linux. It does not execute Apple's genuine iOS runtime.</p>
          </section>
        </aside>
      </main>
      <footer className="text-center text-xs text-gray-600 mt-10">IVSL · iOS Virtual Security Lab · Linux simulated environment</footer>
    </div>
  )
}

function PhoneIcon() {
  return <Smartphone size={23}/>
}

export default App

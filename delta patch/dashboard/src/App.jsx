import { useState, useEffect, useCallback } from 'react'

const API = '/api'
const LATEST_FIRMWARE_URL = 'http://13.63.176.124:9000/firmware/download/test_firmware.bin'
const STEPS = [
  { id: 0, title: 'Overview', short: 'Overview' },
  { id: 1, title: 'Upload firmware', short: 'Firmware' },
  { id: 2, title: 'Create delta patch', short: 'Patch' },
  { id: 3, title: 'Distribute to device', short: 'Distribute' },
  { id: 4, title: 'Done', short: 'Done' },
]

function App() {
  const [step, setStep] = useState(0)
  const [serverOnline, setServerOnline] = useState(null)
  const [devices, setDevices] = useState({})
  const [firmware, setFirmware] = useState([])
  const [patches, setPatches] = useState([])
  const [loading, setLoading] = useState(true)
  const [message, setMessage] = useState(null)
  const [uploadVersion, setUploadVersion] = useState('')
  const [uploadFile, setUploadFile] = useState(null)
  const [createPatch, setCreatePatch] = useState({ old_version: '', new_version: '' })
  const [distribute, setDistribute] = useState({ device_id: '', old_version: '', new_version: '' })
  const [creating, setCreating] = useState(false)
  const [distributing, setDistributing] = useState(false)
  const [uploading, setUploading] = useState(false)

  const fetchAll = useCallback(async () => {
    try {
      const [devRes, fwRes, patchRes] = await Promise.all([
        fetch(`${API}/devices`),
        fetch(`${API}/firmware`),
        fetch(`${API}/patches`),
      ])
      if (devRes.ok) setDevices((await devRes.json()).devices || {})
      if (fwRes.ok) setFirmware((await fwRes.json()).firmware || [])
      if (patchRes.ok) setPatches((await patchRes.json()).patches || [])
      setServerOnline(devRes.ok)
    } catch (_) {
      setServerOnline(false)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchAll()
    const t = setInterval(fetchAll, 10000)
    return () => clearInterval(t)
  }, [fetchAll])

  const showMsg = (text, type = 'info') => {
    setMessage({ text, type })
    setTimeout(() => setMessage(null), 5000)
  }

  const goNext = () => {
    if (step < STEPS.length - 1) setStep(step + 1)
  }
  const goBack = () => {
    if (step > 0) setStep(step - 1)
  }
  const goToStep = (s) => setStep(s)

  const handleUploadFirmware = async (e) => {
    e.preventDefault()
    if (!uploadVersion.trim() || !uploadFile) {
      showMsg('Enter version and select a .bin file', 'error')
      return
    }
    setUploading(true)
    setMessage(null)
    try {
      const form = new FormData()
      form.append('version', uploadVersion.trim())
      form.append('file', uploadFile)
      const res = await fetch('/upload_firmware/', { method: 'POST', body: form })
      const data = await res.json().catch(() => ({}))
      if (res.ok) {
        showMsg(`Firmware ${uploadVersion} uploaded successfully`, 'success')
        setUploadVersion('')
        setUploadFile(null)
        fetchAll()
        goNext()
      } else {
        showMsg(data.detail || 'Upload failed', 'error')
      }
    } catch (err) {
      showMsg('Network error', 'error')
    } finally {
      setUploading(false)
    }
  }

  const handleCreatePatch = async (e) => {
    e.preventDefault()
    if (!createPatch.old_version || !createPatch.new_version) {
      showMsg('Select both from and to version', 'error')
      return
    }
    if (createPatch.old_version === createPatch.new_version) {
      showMsg('From and to version must be different', 'error')
      return
    }
    setCreating(true)
    setMessage(null)
    try {
      const form = new FormData()
      form.append('old_version', createPatch.old_version)
      form.append('new_version', createPatch.new_version)
      const res = await fetch('/make_patch/', { method: 'POST', body: form })
      const data = await res.json().catch(() => ({}))
      if (res.ok) {
        showMsg(`Delta patch created: ${createPatch.old_version} → ${createPatch.new_version}`, 'success')
        fetchAll()
        goNext()
      } else {
        showMsg(data.detail || 'Create patch failed', 'error')
      }
    } catch (err) {
      showMsg('Network error', 'error')
    } finally {
      setCreating(false)
    }
  }

  const handleDistribute = async (e) => {
    e.preventDefault()
    if (!distribute.device_id?.trim() || !distribute.old_version || !distribute.new_version) {
      showMsg('Fill device ID and both versions', 'error')
      return
    }
    setDistributing(true)
    setMessage(null)
    try {
      const form = new FormData()
      form.append('device_id', distribute.device_id.trim())
      form.append('old_version', distribute.old_version)
      form.append('new_version', distribute.new_version)
      const res = await fetch('/instruct_update/', { method: 'POST', body: form })
      const data = await res.json().catch(() => ({}))
      if (res.ok) {
        showMsg(`Update queued for ${distribute.device_id}`, 'success')
        fetchAll()
        goNext()
      } else {
        showMsg(data.detail || 'Distribute failed', 'error')
      }
    } catch (err) {
      showMsg('Network error', 'error')
    } finally {
      setDistributing(false)
    }
  }

  const deviceList = Object.entries(devices)
  const currentStepInfo = STEPS[step]
  const isLastStep = step === STEPS.length - 1
  const isFirstStep = step === 0

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <h1>OTA Update Wizard</h1>
          <span className={`server-status ${serverOnline === true ? 'online' : serverOnline === false ? 'offline' : ''}`}>
            {serverOnline === true ? '● Connected' : serverOnline === false ? '○ Offline' : '…'}
          </span>
        </div>
      </header>

      {step < STEPS.length - 1 && (
        <nav className="wizard-steps">
          <div className="wizard-progress" style={{ '--progress': `${(step / (STEPS.length - 1)) * 100}%` }} />
          <ul className="wizard-step-list">
            {STEPS.filter((s) => s.id < 4).map((s) => (
              <li key={s.id} className={step === s.id ? 'active' : step > s.id ? 'done' : ''}>
                <button type="button" className="wizard-step-btn" onClick={() => goToStep(s.id)}>
                  <span className="wizard-step-num">{s.id + 1}</span>
                  <span className="wizard-step-title">{s.short}</span>
                </button>
              </li>
            ))}
          </ul>
        </nav>
      )}

      {message && (
        <div className={`alert ${message.type}`} role="alert">
          {message.text}
        </div>
      )}

      <main className="wizard-content">
        {loading ? (
          <div className="card wizard-card">
            <p className="loading">Loading…</p>
          </div>
        ) : (
          <>
            {step === 0 && (
              <div className="card wizard-card">
                <h2 className="wizard-card-title">Overview</h2>
                <p className="wizard-card-desc">Review devices, firmware, and patches. Start the wizard to upload firmware, create a delta patch, and distribute it to a device.</p>
                <div className="overview-grid">
                  <section className="overview-block">
                    <h3>Devices</h3>
                    {deviceList.length === 0 ? (
                      <p className="empty">No devices yet. Distribute an update to register one.</p>
                    ) : (
                      <ul className="list">
                        {deviceList.map(([id, d]) => (
                          <li key={id}>
                            <span><strong>{id}</strong> <span className="muted">v{d.version}</span></span>
                            {d.pending_update ? (
                              <span className="badge pending">{d.pending_update.old_version} → {d.pending_update.new_version}</span>
                            ) : (
                              <span className="badge ok">Up to date</span>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>
                  <section className="overview-block">
                    <h3>Firmware versions</h3>
                    {firmware.length === 0 ? (
                      <p className="empty">None. Go to step 1 to upload.</p>
                    ) : (
                      <ul className="list">
                        {firmware.map((f) => (
                          <li key={f.version}>
                            <span>v{f.version}</span>
                            <span className="muted">{(f.size / 1024).toFixed(1)} KB</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>
                  <section className="overview-block">
                    <h3>Delta patches (REM)</h3>
                    {patches.length === 0 ? (
                      <p className="empty">None. Go to step 2 to create.</p>
                    ) : (
                      <ul className="list">
                        {patches.map((p) => (
                          <li key={`${p.old_version}-${p.new_version}`}>
                            <span>v{p.old_version} → v{p.new_version}</span>
                            <span className="muted">{(p.enc_size / 1024).toFixed(1)} KB</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>
                </div>
                <div className="wizard-actions">
                  <a href={LATEST_FIRMWARE_URL} target="_blank" rel="noopener noreferrer" className="btn secondary">
                    Download latest firmware
                  </a>
                  <button type="button" className="btn" onClick={() => goToStep(1)}>
                    Start wizard →
                  </button>
                </div>
              </div>
            )}

            {step === 1 && (
              <div className="card wizard-card">
                <h2 className="wizard-card-title">Step 1: Upload firmware</h2>
                <p className="wizard-card-desc">Upload a firmware .bin file and assign a version (e.g. 1.0.0). You need at least two versions to create a delta patch.</p>
                <form onSubmit={handleUploadFirmware} className="wizard-form">
                  <div className="form-group">
                    <label htmlFor="fw-version">Version</label>
                    <input
                      id="fw-version"
                      type="text"
                      placeholder="e.g. 1.0.0"
                      value={uploadVersion}
                      onChange={(e) => setUploadVersion(e.target.value)}
                    />
                  </div>
                  <div className="form-group">
                    <label htmlFor="fw-file">Firmware file (.bin)</label>
                    <input
                      id="fw-file"
                      type="file"
                      accept=".bin"
                      onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
                    />
                    {uploadFile && <span className="muted file-name">{uploadFile.name}</span>}
                  </div>
                  <div className="wizard-actions">
                    <button type="button" className="btn secondary" onClick={goBack}>← Back</button>
                    <button type="submit" className="btn" disabled={uploading || !uploadVersion.trim() || !uploadFile}>
                      {uploading ? 'Uploading…' : 'Upload & continue'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {step === 2 && (
              <div className="card wizard-card">
                <h2 className="wizard-card-title">Step 2: Create delta patch</h2>
                <p className="wizard-card-desc">Generate a REM-encrypted delta patch (bsdiff) between two firmware versions. The patch and signature will be saved on the server.</p>
                <form onSubmit={handleCreatePatch} className="wizard-form">
                  <div className="form-row-inline">
                    <div className="form-group">
                      <label htmlFor="patch-from">From version</label>
                      <select
                        id="patch-from"
                        value={createPatch.old_version}
                        onChange={(e) => setCreatePatch((s) => ({ ...s, old_version: e.target.value }))}
                      >
                        <option value="">Select</option>
                        {firmware.map((f) => (
                          <option key={f.version} value={f.version}>{f.version}</option>
                        ))}
                      </select>
                    </div>
                    <div className="form-group">
                      <label htmlFor="patch-to">To version</label>
                      <select
                        id="patch-to"
                        value={createPatch.new_version}
                        onChange={(e) => setCreatePatch((s) => ({ ...s, new_version: e.target.value }))}
                      >
                        <option value="">Select</option>
                        {firmware.map((f) => (
                          <option key={f.version} value={f.version}>{f.version}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <div className="wizard-actions">
                    <button type="button" className="btn secondary" onClick={goBack}>← Back</button>
                    <button type="submit" className="btn" disabled={creating || !createPatch.old_version || !createPatch.new_version || createPatch.old_version === createPatch.new_version}>
                      {creating ? 'Creating…' : 'Create patch & continue'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {step === 3 && (
              <div className="card wizard-card">
                <h2 className="wizard-card-title">Step 3: Distribute to device</h2>
                <p className="wizard-card-desc">Queue an OTA update for a device. The ESP32 will fetch the patch and signature when it checks in, then verify and apply.</p>
                <form onSubmit={handleDistribute} className="wizard-form">
                  <div className="form-group">
                    <label htmlFor="device-id">Device ID</label>
                    <input
                      id="device-id"
                      type="text"
                      placeholder="e.g. esp32_01"
                      value={distribute.device_id}
                      onChange={(e) => setDistribute((s) => ({ ...s, device_id: e.target.value }))}
                      list="device-ids"
                    />
                    <datalist id="device-ids">
                      {deviceList.map(([id]) => <option key={id} value={id} />)}
                    </datalist>
                  </div>
                  <div className="form-row-inline">
                    <div className="form-group">
                      <label htmlFor="dist-from">Current version (on device)</label>
                      <select
                        id="dist-from"
                        value={distribute.old_version}
                        onChange={(e) => setDistribute((s) => ({ ...s, old_version: e.target.value }))}
                      >
                        <option value="">Select</option>
                        {firmware.map((f) => (
                          <option key={f.version} value={f.version}>{f.version}</option>
                        ))}
                      </select>
                    </div>
                    <div className="form-group">
                      <label htmlFor="dist-to">Target version</label>
                      <select
                        id="dist-to"
                        value={distribute.new_version}
                        onChange={(e) => setDistribute((s) => ({ ...s, new_version: e.target.value }))}
                      >
                        <option value="">Select</option>
                        {firmware.map((f) => (
                          <option key={f.version} value={f.version}>{f.version}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                  <div className="wizard-actions">
                    <button type="button" className="btn secondary" onClick={goBack}>← Back</button>
                    <button type="submit" className="btn" disabled={distributing || !distribute.device_id?.trim() || !distribute.old_version || !distribute.new_version}>
                      {distributing ? 'Queuing…' : 'Queue update & finish'}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {step === 4 && (
              <div className="card wizard-card wizard-done">
                <div className="done-icon">✓</div>
                <h2 className="wizard-card-title">Update queued</h2>
                <p className="wizard-card-desc">The device will receive the update on its next check. You can start another flow or go back to overview.</p>
                <div className="wizard-actions">
                  <button type="button" className="btn secondary" onClick={() => goToStep(0)}>Overview</button>
                  <button type="button" className="btn" onClick={() => goToStep(1)}>Start another wizard</button>
                </div>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  )
}

export default App

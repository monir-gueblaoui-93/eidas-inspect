import { useRef, useState } from 'react'
import { IconUpload } from '../icons.jsx'

export default function UploadZone({ onFileSelected }) {
  const inputRef = useRef(null)
  const [dragging, setDragging] = useState(false)

  function openPicker() {
    inputRef.current?.click()
  }

  function handleKeyDown(event) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      openPicker()
    }
  }

  function handleDrop(event) {
    event.preventDefault()
    setDragging(false)
    const file = event.dataTransfer.files?.[0]
    if (file) onFileSelected(file)
  }

  function handleInputChange(event) {
    const file = event.target.files?.[0]
    if (file) onFileSelected(file)
    event.target.value = '' // allow re-selecting the same file next time
  }

  return (
    <div
      className={`upload-zone${dragging ? ' upload-zone--dragging' : ''}`}
      role="button"
      tabIndex={0}
      aria-label="Upload a PDF to verify"
      onClick={openPicker}
      onKeyDown={handleKeyDown}
      onDragOver={(e) => {
        e.preventDefault()
        setDragging(true)
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
    >
      <div className="upload-zone__icon">
        <IconUpload size={32} />
      </div>
      <p className="upload-zone__title">Drop your PDF here</p>
      <p className="upload-zone__hint">or tap to choose a file · PDF only · up to 50 MB</p>
      <input
        ref={inputRef}
        type="file"
        accept="application/pdf,.pdf"
        onChange={handleInputChange}
        hidden
      />
    </div>
  )
}

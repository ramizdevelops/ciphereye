import { useDropzone } from 'react-dropzone'
import { Upload } from 'lucide-react'
import clsx from 'clsx'

interface FileDropzoneProps {
  onFile: (file: File) => void
  accept?: Record<string, string[]>
  label?: string
  hint?: string
}

export default function FileDropzone({ onFile, accept, label, hint }: FileDropzoneProps) {
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: files => files[0] && onFile(files[0]),
    accept,
    multiple: false,
  })

  return (
    <div
      {...getRootProps()}
      className={clsx(
        'border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors',
        isDragActive
          ? 'border-accent-cyan bg-surface-700'
          : 'border-surface-500 hover:border-surface-400'
      )}
    >
      <input {...getInputProps()} />
      <Upload size={32} className="mx-auto mb-3 text-gray-500" />
      <p className="text-sm font-mono text-gray-300">
        {label || 'Drop file here or click to upload'}
      </p>
      {hint && <p className="text-xs text-gray-500 mt-1 font-mono">{hint}</p>}
    </div>
  )
}

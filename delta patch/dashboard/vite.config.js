import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/dashboard/',
  server: {
    port: 3000,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      '/upload_firmware': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      '/make_patch': { target: 'http://127.0.0.1:8000', changeOrigin: true },
      '/instruct_update': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
})

import { defineConfig } from 'vite';
export default defineConfig({
  server: { host: '127.0.0.1', port: 8911, strictPort: true, proxy: { '/api': 'http://127.0.0.1:8910' } },
  preview: { host: '127.0.0.1' },
  build: { sourcemap: false }
});

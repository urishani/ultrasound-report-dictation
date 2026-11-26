import { defineConfig } from 'vite';

export default defineConfig({
  // Relative base keeps assets working on project Pages
  // (https://urishani.github.io/ultrasound-report-dictation/) and locally.
  base: './',
  server: {
    open: false,
  },
  preview: {
    open: false,
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
});

import {defineConfig} from 'vite';
export default defineConfig({root:'web',build:{outDir:'../internal/webassets/public',emptyOutDir:true},server:{proxy:{'/api':'http://127.0.0.1:8787','/s/':'http://127.0.0.1:8787','/delivery/':'http://127.0.0.1:8787'}}});

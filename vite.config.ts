import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({plugins:[react()],clearScreen:false,server:{strictPort:true,port:1420},envPrefix:["VITE_","TAURI_ENV_*"],build:{target:"es2022",sourcemap:false}});

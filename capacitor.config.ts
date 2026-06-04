import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.quranaudio.app',
  appName: 'Quran Audio App',
  webDir: 'dist',
  server: {
    androidScheme: 'https'
  }
};

export default config;

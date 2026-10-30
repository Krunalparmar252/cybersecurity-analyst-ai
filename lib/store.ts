import { create } from 'zustand';

interface AppState {
  theme: 'dark' | 'light';
  motionPreference: 'full' | 'reduced';
  commandPaletteOpen: boolean;
  activeScanId: string | null;
  offlineMode: boolean;
  dynamicExploitMode: boolean;
  sidebarCollapsed: boolean;

  setTheme: (theme: 'dark' | 'light') => void;
  toggleTheme: () => void;
  setMotionPreference: (pref: 'full' | 'reduced') => void;
  setCommandPaletteOpen: (open: boolean) => void;
  setActiveScanId: (id: string | null) => void;
  setOfflineMode: (offline: boolean) => void;
  setDynamicExploitMode: (dynamic: boolean) => void;
  toggleSidebar: () => void;
}

export const useAppStore = create<AppState>((set) => ({
  theme: 'dark',
  motionPreference: 'full',
  commandPaletteOpen: false,
  activeScanId: 'SCN-2026-0941',
  offlineMode: false,
  dynamicExploitMode: true,
  sidebarCollapsed: false,

  setTheme: (theme) => {
    if (typeof document !== 'undefined') {
      if (theme === 'light') {
        document.documentElement.classList.add('light');
      } else {
        document.documentElement.classList.remove('light');
      }
    }
    set({ theme });
  },

  toggleTheme: () =>
    set((state) => {
      const nextTheme = state.theme === 'dark' ? 'light' : 'dark';
      if (typeof document !== 'undefined') {
        if (nextTheme === 'light') {
          document.documentElement.classList.add('light');
        } else {
          document.documentElement.classList.remove('light');
        }
      }
      return { theme: nextTheme };
    }),

  setMotionPreference: (motionPreference) => set({ motionPreference }),
  setCommandPaletteOpen: (commandPaletteOpen) => set({ commandPaletteOpen }),
  setActiveScanId: (activeScanId) => set({ activeScanId }),
  setOfflineMode: (offlineMode) => set({ offlineMode }),
  setDynamicExploitMode: (dynamicExploitMode) => set({ dynamicExploitMode }),
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
}));


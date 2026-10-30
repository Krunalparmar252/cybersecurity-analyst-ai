import { describe, it, expect, beforeEach } from 'vitest';
import { useAppStore } from '@/lib/store';

describe('useAppStore', () => {
  beforeEach(() => {
    useAppStore.setState({
      theme: 'dark',
      sidebarCollapsed: false,
      commandPaletteOpen: false,
    });
  });

  it('toggles theme between dark and light', () => {
    expect(useAppStore.getState().theme).toBe('dark');

    useAppStore.getState().toggleTheme();
    expect(useAppStore.getState().theme).toBe('light');

    useAppStore.getState().toggleTheme();
    expect(useAppStore.getState().theme).toBe('dark');
  });

  it('toggles sidebar state', () => {
    expect(useAppStore.getState().sidebarCollapsed).toBe(false);

    useAppStore.getState().toggleSidebar();
    expect(useAppStore.getState().sidebarCollapsed).toBe(true);

    useAppStore.getState().toggleSidebar();
    expect(useAppStore.getState().sidebarCollapsed).toBe(false);
  });

  it('sets command palette state', () => {
    expect(useAppStore.getState().commandPaletteOpen).toBe(false);

    useAppStore.getState().setCommandPaletteOpen(true);
    expect(useAppStore.getState().commandPaletteOpen).toBe(true);

    useAppStore.getState().setCommandPaletteOpen(false);
    expect(useAppStore.getState().commandPaletteOpen).toBe(false);
  });
});

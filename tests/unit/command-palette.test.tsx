import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import CommandPalette from '@/components/ui/CommandPalette';
import { useAppStore } from '@/lib/store';

// Mock next/navigation
vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: vi.fn(),
  }),
}));

describe('CommandPalette Component', () => {
  beforeEach(() => {
    useAppStore.setState({
      commandPaletteOpen: false,
    });
  });

  it('renders nothing when closed', () => {
    const { container } = render(<CommandPalette />);
    expect(container.firstChild).toBeNull();
  });

  it('opens and closes via global Ctrl+K shortcut', () => {
    render(<CommandPalette />);

    expect(screen.queryByPlaceholderText(/Type a command/i)).toBeNull();

    // Trigger Ctrl+K
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(useAppStore.getState().commandPaletteOpen).toBe(true);
    expect(screen.getByPlaceholderText(/Type a command/i)).toBeInTheDocument();

    // Trigger Ctrl+K again to toggle closed
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
    expect(useAppStore.getState().commandPaletteOpen).toBe(false);
    expect(screen.queryByPlaceholderText(/Type a command/i)).toBeNull();
  });

  it('closes when Escape key is pressed', () => {
    useAppStore.setState({ commandPaletteOpen: true });
    render(<CommandPalette />);

    expect(screen.getByPlaceholderText(/Type a command/i)).toBeInTheDocument();

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(useAppStore.getState().commandPaletteOpen).toBe(false);
    expect(screen.queryByPlaceholderText(/Type a command/i)).toBeNull();
  });

  it('filters results when typing into search input', () => {
    useAppStore.setState({ commandPaletteOpen: true });
    render(<CommandPalette />);

    const input = screen.getByPlaceholderText(/Type a command/i);
    fireEvent.change(input, { target: { value: 'Findings' } });

    expect(screen.getByText(/View Vulnerability Findings/i)).toBeInTheDocument();
    expect(screen.queryByText(/Traffic & Anomaly Telemetry/i)).toBeNull();
  });
});

'use client';

import React, { useEffect, useRef } from 'react';
import { gsap } from '@/lib/motion';

export default function CustomCursor() {
  const cursorRef = useRef<HTMLDivElement>(null);
  const dotRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Only enable on desktop non-touch screens with pointer
    if (typeof window === 'undefined') return;
    if (window.matchMedia('(pointer: coarse)').matches) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

    const cursor = cursorRef.current;
    const dot = dotRef.current;
    if (!cursor || !dot) return;

    // quickTo for high-performance 60fps tracking without per-event tween allocations
    const dotX = gsap.quickTo(dot, 'x', { duration: 0.08, ease: 'none' });
    const dotY = gsap.quickTo(dot, 'y', { duration: 0.08, ease: 'none' });

    const cursorX = gsap.quickTo(cursor, 'x', { duration: 0.22, ease: 'power2.out' });
    const cursorY = gsap.quickTo(cursor, 'y', { duration: 0.22, ease: 'power2.out' });

    const onMouseMove = (e: MouseEvent) => {
      dotX(e.clientX);
      dotY(e.clientY);
      cursorX(e.clientX);
      cursorY(e.clientY);
    };

    let isHovering = false;
    const onMouseOver = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null;
      if (!target) return;
      const clickable = target.closest('a, button, input, select, textarea, [role="button"]');
      if (clickable && !isHovering) {
        isHovering = true;
        gsap.to(cursor, {
          scale: 1.75,
          borderColor: '#C6FF3D',
          backgroundColor: 'rgba(198, 255, 61, 0.08)',
          duration: 0.2,
          overwrite: 'auto',
        });
      } else if (!clickable && isHovering) {
        isHovering = false;
        gsap.to(cursor, {
          scale: 1,
          borderColor: 'rgba(255, 255, 255, 0.35)',
          backgroundColor: 'transparent',
          duration: 0.2,
          overwrite: 'auto',
        });
      }
    };

    window.addEventListener('mousemove', onMouseMove, { passive: true });
    document.addEventListener('mouseover', onMouseOver, { passive: true });

    return () => {
      window.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseover', onMouseOver);
    };
  }, []);

  return (
    <>
      <div
        ref={cursorRef}
        className="pointer-events-none fixed top-0 left-0 z-[9999] -translate-x-1/2 -translate-y-1/2 rounded-full border border-white/40 h-7 w-7 transition-colors hidden md:block"
      />
      <div
        ref={dotRef}
        className="pointer-events-none fixed top-0 left-0 z-[9999] -translate-x-1/2 -translate-y-1/2 rounded-full bg-signal h-1 w-1 hidden md:block"
      />
    </>
  );
}

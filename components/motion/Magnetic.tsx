'use client';

import React, { useRef } from 'react';
import { gsap, prefersReducedMotion } from '@/lib/motion';

interface MagneticProps {
  children: React.ReactElement<{ className?: string }>;
  strength?: number;
  className?: string;
}

export default function Magnetic({
  children,
  strength = 0.28,
  className = 'inline-block',
}: MagneticProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (prefersReducedMotion()) return;
    const el = containerRef.current;
    if (!el) return;

    const rect = el.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;

    const deltaX = (e.clientX - centerX) * strength;
    const deltaY = (e.clientY - centerY) * strength;

    gsap.to(el, {
      x: deltaX,
      y: deltaY,
      duration: 0.35,
      ease: 'power2.out',
    });
  };

  const handleMouseLeave = () => {
    if (prefersReducedMotion()) return;
    const el = containerRef.current;
    if (!el) return;

    gsap.to(el, {
      x: 0,
      y: 0,
      duration: 0.55,
      ease: 'elastic.out(1, 0.4)',
    });
  };

  return (
    <div
      ref={containerRef}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      className={className}
      style={{ willChange: 'transform' }}
    >
      {children}
    </div>
  );
}


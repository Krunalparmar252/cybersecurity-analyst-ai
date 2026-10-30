'use client';

import React, { useRef } from 'react';
import { gsap, ScrollTrigger, useGSAP, prefersReducedMotion } from '@/lib/motion';

interface PinnedSceneProps {
  children: (progress: number) => React.ReactNode;
  heightMultiplier?: number;
  className?: string;
  onUpdate?: (progress: number) => void;
}

export default function PinnedScene({
  children,
  heightMultiplier = 4,
  className = '',
  onUpdate,
}: PinnedSceneProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const pinRef = useRef<HTMLDivElement>(null);
  const [currentProgress, setCurrentProgress] = React.useState(0);

  useGSAP(
    () => {
      const container = containerRef.current;
      const pin = pinRef.current;
      if (!container || !pin) return;

      const mm = gsap.matchMedia();

      // Only pin on screens > 768px and when reduced motion is not preferred
      mm.add(
        '(min-width: 769px) and (prefers-reduced-motion: no-preference)',
        () => {
          const trigger = ScrollTrigger.create({
            trigger: container,
            start: 'top top',
            end: `+=${window.innerHeight * heightMultiplier}`,
            pin: pin,
            scrub: 0.6,
            anticipatePin: 1,
            onUpdate: (self) => {
              setCurrentProgress(self.progress);
              if (onUpdate) onUpdate(self.progress);
            },
          });

          return () => {
            trigger.kill();
          };
        }
      );

      // On mobile / reduced motion, simple static flow
      mm.add('(max-width: 768px)', () => {
        setCurrentProgress(1);
      });

      return () => mm.revert();
    },
    { scope: containerRef, dependencies: [heightMultiplier] }
  );

  return (
    <div
      ref={containerRef}
      className={`relative w-full ${className}`}
      style={{
        height: typeof window !== 'undefined' && window.innerWidth > 768 ? `${heightMultiplier * 100}vh` : 'auto',
      }}
    >
      <div
        ref={pinRef}
        className="relative w-full md:h-screen flex flex-col justify-center overflow-hidden"
      >
        {children(currentProgress)}
      </div>
    </div>
  );
}


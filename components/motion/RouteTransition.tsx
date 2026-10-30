'use client';

import React, { useEffect, useRef } from 'react';
import { usePathname } from 'next/navigation';
import { gsap, ScrollTrigger } from '@/lib/motion';

export default function RouteTransition({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const overlayRef = useRef<HTMLDivElement>(null);
  const accentLineRef = useRef<HTMLDivElement>(null);
  const titleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Only play transition on marketing routes
    const isMarketing = pathname === '/' || pathname === '/architecture';
    if (!isMarketing) return;

    const overlay = overlayRef.current;
    const accentLine = accentLineRef.current;
    const title = titleRef.current;
    if (!overlay || !accentLine) return;

    const isReduced = typeof window !== 'undefined' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (isReduced) {
      ScrollTrigger.refresh();
      return;
    }

    const routeName =
      pathname === '/'
        ? 'OVERVIEW // ARCHITECTURE'
        : 'ARCHITECTURE // SPECIFICATION';

    if (title) title.innerText = routeName;

    const tl = gsap.timeline();

    // Fast 0.3s reveal out on route change
    tl.fromTo(
      overlay,
      { clipPath: 'polygon(0 0, 100% 0, 100% 100%, 0 100%)', opacity: 1 },
      {
        clipPath: 'polygon(0 0, 100% 0, 100% 0%, 0 0%)',
        duration: 0.3,
        ease: 'power3.inOut',
        delay: 0.02,
        onComplete: () => {
          ScrollTrigger.refresh();
        },
      }
    );

    return () => {
      // Clean up orphaned ScrollTrigger instances on route change
      ScrollTrigger.getAll().forEach((st) => {
        if (!st.vars.trigger || !document.contains(st.vars.trigger as Node)) {
          st.kill();
        }
      });
    };
  }, [pathname]);

  return (
    <>
      <div
        ref={overlayRef}
        aria-hidden="true"
        className="pointer-events-none fixed inset-0 z-[9990] bg-canvas flex flex-col items-center justify-center opacity-0"
        style={{
          clipPath: 'polygon(0 0, 100% 0, 100% 0%, 0 0%)',
        }}
      >
        <div ref={accentLineRef} className="w-16 h-[2px] bg-signal mb-4" />
        <div
          ref={titleRef}
          className="font-mono text-xs tracking-widest text-text-secondary uppercase"
        >
          AUTONOMOUS CYBERSECURITY ANALYST
        </div>
      </div>
      {children}
    </>
  );
}

import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { CustomEase } from 'gsap/CustomEase';
import { useGSAP } from '@gsap/react';

// Register core plugins safely on client
if (typeof window !== 'undefined') {
  gsap.registerPlugin(ScrollTrigger, CustomEase, useGSAP);

  // Precision signal ease: crisp attack, soft natural settle
  try {
    CustomEase.create('signal', 'M0,0 C0.16,1 0.3,1 1,1');
    CustomEase.create('signalOut', 'M0,0 C0.2,0 0.2,1 1,1');
  } catch (e) {
    // Fallback if already defined
  }
}

export { gsap, ScrollTrigger, CustomEase, useGSAP };

// Motion design constants
export const MOTION = {
  durations: {
    fast: 0.35,
    base: 0.65,
    slow: 0.95,
    cinematic: 1.25,
  },
  staggers: {
    tight: 0.04,
    base: 0.06,
    loose: 0.08,
  },
  ease: {
    signal: 'signal',
    soft: 'power2.out',
    snappy: 'power3.out',
  },
};

/**
 * Checks if the user has requested reduced motion
 */
export const prefersReducedMotion = (): boolean => {
  if (typeof window === 'undefined') return false;
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
};

/**
 * Safe GSAP timeline creator with reduced motion support
 */
export const createSafeTimeline = (vars?: gsap.TimelineVars): gsap.core.Timeline => {
  const isReduced = prefersReducedMotion();
  const tl = gsap.timeline(vars);
  if (isReduced) {
    tl.timeScale(100); // effectively instantaneous
  }
  return tl;
};
